"""Traffic summary — the first thing an analyst wants from a capture.

    python -m netsentinel.cli summary capture.pcap [--top 10] [--json out.json]

Computes, in one streaming pass with bounded memory per key:
  * capture window, packets, bytes, average rate
  * protocol mix (TCP / UDP / ICMP / other)
  * top talkers (source IPs by bytes sent), top destinations (by bytes received)
  * busiest destination ports and the heaviest conversations (IP pairs)
  * internal vs. external split using the same HOME_NET as the rule engine
"""
from __future__ import annotations

import ipaddress
from collections import Counter
from typing import Iterable

from .flows import Packet
from .rules import parse_home_net

PROTO_NAMES = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}
WELL_KNOWN = {20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 80: "http",
              110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
              465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql",
              3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt"}


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def summarize(packets: Iterable[Packet], top: int = 10, home_net=None) -> dict:
    nets = parse_home_net(home_net)

    def internal(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a.version == n.version and a in n for n in nets)

    n = total = 0
    first = last = None
    proto_pkts: Counter = Counter()
    proto_bytes: Counter = Counter()
    src_bytes: Counter = Counter()
    dst_bytes: Counter = Counter()
    port_pkts: Counter = Counter()
    pair_bytes: Counter = Counter()
    direction: Counter = Counter()
    syn_only = 0

    for p in packets:
        n += 1
        total += p.length
        first = p.ts if first is None else min(first, p.ts)
        last = p.ts if last is None else max(last, p.ts)
        pname = PROTO_NAMES.get(p.proto, f"proto {p.proto}")
        proto_pkts[pname] += 1
        proto_bytes[pname] += p.length
        src_bytes[p.src] += p.length
        dst_bytes[p.dst] += p.length
        if p.proto in (6, 17) and p.dport:
            port_pkts[(pname, p.dport)] += 1
        pair_bytes[tuple(sorted((p.src, p.dst)))] += p.length
        si, di = internal(p.src), internal(p.dst)
        direction["internal→internal" if si and di else "internal→external" if si
                  else "external→internal" if di else "external→external"] += p.length
        if p.proto == 6 and p.flags == "S":
            syn_only += 1

    duration = (last - first) if n else 0.0

    def ranked(counter, k):
        return counter.most_common(k)

    return {
        "packets": n,
        "bytes": total,
        "start": first,
        "end": last,
        "duration_s": round(duration, 3),
        "avg_bps": round(total * 8 / duration, 1) if duration > 0 else None,
        "protocols": [{"protocol": k, "packets": v, "bytes": proto_bytes[k]} for k, v in ranked(proto_pkts, 10)],
        "top_sources": [{"ip": k, "bytes": v, "internal": internal(k)} for k, v in ranked(src_bytes, top)],
        "top_destinations": [{"ip": k, "bytes": v, "internal": internal(k)} for k, v in ranked(dst_bytes, top)],
        "top_ports": [{"port": port, "protocol": proto, "service": WELL_KNOWN.get(port, ""), "packets": v}
                      for (proto, port), v in ranked(port_pkts, top)],
        "top_conversations": [{"a": a, "b": b, "bytes": v} for (a, b), v in ranked(pair_bytes, top)],
        "direction_bytes": dict(direction),
        "tcp_syn_only_packets": syn_only,
        "unique_hosts": len(set(src_bytes) | set(dst_bytes)),
    }


def format_summary(s: dict) -> str:
    if not s["packets"]:
        return "No IP packets in this capture."
    rate = f" · avg {s['avg_bps'] / 1e6:.2f} Mbit/s" if s["avg_bps"] else ""
    out = [f"{s['packets']:,} packets · {_human_bytes(s['bytes'])} · {s['duration_s']:.1f}s{rate} · "
           f"{s['unique_hosts']} hosts"]
    out.append("Protocols:   " + ", ".join(f"{p['protocol']} {p['packets'] * 100 / s['packets']:.0f}%"
                                         for p in s["protocols"]))
    out.append("Direction:   " + ", ".join(f"{k} {_human_bytes(v)}" for k, v in
                                         sorted(s["direction_bytes"].items(), key=lambda kv: -kv[1])))

    def section(title, rows, fmt):
        out.append(title)
        out.extend("  " + fmt(r) for r in rows)

    tag = lambda r: "" if r["internal"] else "  (external)"  # noqa: E731
    section("Top talkers (bytes sent):", s["top_sources"], lambda r: f"{r['ip']:<40} {_human_bytes(r['bytes']):>10}{tag(r)}")
    section("Top destinations (bytes received):", s["top_destinations"],
            lambda r: f"{r['ip']:<40} {_human_bytes(r['bytes']):>10}{tag(r)}")
    section("Busiest destination ports:", s["top_ports"],
            lambda r: f"{r['protocol']}/{r['port']:<6} {r['service']:<11} {r['packets']:>8,} pkts")
    section("Heaviest conversations:", s["top_conversations"],
            lambda r: f"{r['a']} ↔ {r['b']}  {_human_bytes(r['bytes'])}")
    if s["tcp_syn_only_packets"]:
        out.append(f"TCP SYN-only packets: {s['tcp_syn_only_packets']:,} (high counts suggest scanning or SYN floods)")
    return "\n".join(out)
