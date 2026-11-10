"""Stateful, window-based detection rules.

Some attacks are invisible at the single-flow level (one SYN to one port looks
harmless) and only appear in aggregate: one source touching hundreds of ports,
thousands of half-open connections to one host, dozens of short SSH sessions.
These rules watch sliding windows over finished flows and complement the ML
models. Each rule has a cooldown so a single attack produces one alert, not
thousands.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass

from .flows import TCP, UDP, Flow


# HOME_NET, like Snort/Suricata's $HOME_NET variable (RFC 1918 by default)
DEFAULT_HOME_NET = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


def parse_home_net(spec) -> list:
    """Parse a HOME_NET definition into a list of networks.

    Accepts a comma/space separated string ("10.0.0.0/8, 100.64.0.0/10"),
    a Snort-style bracketed list ("[10.0.0.0/8,192.168.1.0/24]"), single IPs,
    or any iterable of those. Raises ValueError on an invalid entry.
    """
    if spec is None:
        spec = DEFAULT_HOME_NET
    if isinstance(spec, str):
        spec = spec.strip().strip("[]").replace(",", " ").split()
    nets = [ipaddress.ip_network(str(s).strip(), strict=False) for s in spec if str(s).strip()]
    if not nets:
        raise ValueError("HOME_NET must contain at least one network")
    return nets


@dataclass
class RuleHit:
    rule: str
    attack: str
    src: str
    dst: str
    ts: float
    detail: str
    severity: str


class RuleEngine:
    def __init__(self, scan_ports=25, scan_window=60, flood_flows=100, flood_window=10,
                 brute_flows=10, brute_window=60, dns_len=150, dns_count=20, cooldown=120,
                 exfil_bytes=1_000_000, exfil_ratio=10.0, rare_peers=2, warmup_flows=200,
                 home_net=None):
        self.cfg = dict(scan_ports=scan_ports, scan_window=scan_window, flood_flows=flood_flows,
                        flood_window=flood_window, brute_flows=brute_flows, brute_window=brute_window,
                        dns_len=dns_len, dns_count=dns_count, exfil_bytes=exfil_bytes,
                        exfil_ratio=exfil_ratio, rare_peers=rare_peers, warmup_flows=warmup_flows)
        self.home_net = parse_home_net(home_net)
        self.peers: dict[str, set] = defaultdict(set)  # external dst -> internal hosts that talked to it
        self.seen_flows = 0
        self.cooldown = cooldown
        self.scan: dict[tuple, deque] = defaultdict(deque)     # (src,dst) -> (ts, port)
        self.halfopen: dict[str, deque] = defaultdict(deque)   # dst -> ts
        self.ssh: dict[tuple, deque] = defaultdict(deque)      # (src,dst) -> ts
        self.dns: dict[str, deque] = defaultdict(deque)        # src -> ts
        self.last_fired: dict[tuple, float] = {}

    def _fire(self, key, ts, hit: RuleHit) -> list[RuleHit]:
        if ts - self.last_fired.get(key, -1e18) < self.cooldown:
            return []
        self.last_fired[key] = ts
        return [hit]

    @staticmethod
    def _trim(d: deque, now: float, window: float):
        while d and now - (d[0][0] if isinstance(d[0], tuple) else d[0]) > window:
            d.popleft()

    def _internal(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in self.home_net)

    def observe(self, f: Flow) -> list[RuleHit]:
        c, ts, hits = self.cfg, f.start, []
        self.seen_flows += 1
        if self._internal(f.src) and not self._internal(f.dst):
            self.peers[f.dst].add(f.src)
            up = sum(p.length for p in f.fwd); down = sum(p.length for p in f.bwd)
            # R5: big one-way upload to a destination almost nobody else on the network uses
            if (self.seen_flows > c["warmup_flows"] and up >= c["exfil_bytes"] and up / (down + 1) >= c["exfil_ratio"]
                    and len(self.peers[f.dst]) <= c["rare_peers"]):
                hits += self._fire(("exfil", f.src, f.dst), ts, RuleHit(
                    "R5-EXFIL", "Exfiltration", f.src, f.dst, ts,
                    f"{up / 1e6:.1f} MB uploaded to rare external host (contacted by {len(self.peers[f.dst])} internal host(s))",
                    "critical"))
        pk = f.fwd + f.bwd
        syn_only = f.proto == TCP and all(p.flags in ("S", "SA", "RA", "R") for p in pk)

        if f.proto == TCP:
            d = self.scan[(f.src, f.dst)]
            d.append((ts, f.dport)); self._trim(d, ts, c["scan_window"])
            ports = {p for _, p in d}
            if len(ports) >= c["scan_ports"]:
                hits += self._fire(("scan", f.src, f.dst), ts, RuleHit(
                    "R1-PORTSCAN", "PortScan", f.src, f.dst, ts,
                    f"{len(ports)} distinct ports probed in {c['scan_window']}s", "medium"))

        # half-open: client only ever sent SYN (handshake never completed).
        # A flood needs many *distinct* sources, which separates it from a port scan.
        if syn_only and f.fwd and all(p.flags == "S" for p in f.fwd):
            d = self.halfopen[f.dst]
            d.append((ts, f.src)); self._trim(d, ts, c["flood_window"])
            if len(d) >= c["flood_flows"] and len({s for _, s in d}) >= c["flood_flows"] // 4:
                hits += self._fire(("flood", f.dst), ts, RuleHit(
                    "R2-SYNFLOOD", "DoS-SYNFlood", "multiple", f.dst, ts,
                    f"{len(d)} half-open connections in {c['flood_window']}s", "high"))

        if f.proto == TCP and f.dport == 22 and len(pk) < 25:
            d = self.ssh[(f.src, f.dst)]
            d.append(ts); self._trim(d, ts, c["brute_window"])
            if len(d) >= c["brute_flows"]:
                hits += self._fire(("brute", f.src, f.dst), ts, RuleHit(
                    "R3-SSHBRUTE", "SSH-BruteForce", f.src, f.dst, ts,
                    f"{len(d)} short SSH sessions in {c['brute_window']}s", "high"))

        if f.proto == UDP and f.dport == 53 and f.fwd and max(p.payload for p in f.fwd) >= c["dns_len"]:
            d = self.dns[f.src]
            d.append(ts); self._trim(d, ts, 60)
            if len(d) >= c["dns_count"]:
                hits += self._fire(("dns", f.src), ts, RuleHit(
                    "R4-DNSTUNNEL", "DNS-Tunneling", f.src, f.dst, ts,
                    f"{len(d)} oversized DNS queries (≥{c['dns_len']} B) in 60s", "high"))
        return hits
