"""Labelled network-traffic simulator.

Generates packet streams for a small office network (10.0.0.0/24) with normal
user traffic and six attack families. It lets the whole IDS pipeline
(packets -> flows -> features -> models -> alerts) run and be tested offline,
and it can write a real .pcap so the same traffic can be opened in Wireshark.

For the evaluation chapter, train on CIC-IDS2017 instead (see train.py).
"""
from __future__ import annotations

import random
from typing import Iterator

from .flows import ICMP, TCP, UDP, Packet

CLIENTS = [f"10.0.0.{i}" for i in range(10, 40)]
SERVERS = {"web": "10.0.0.5", "ssh": "10.0.0.6", "dns": "10.0.0.2", "db": "10.0.0.7"}
INTERNET = ["142.250.183.14", "151.101.1.69", "104.16.132.229", "13.107.42.14", "52.95.110.1"]
ATTACKERS = ["203.0.113.66", "198.51.100.23", "192.0.2.150"]
ATTACK_TYPES = ["DoS-SYNFlood", "PortScan", "SSH-BruteForce", "DNS-Tunneling", "Slowloris", "Exfiltration"]


class Sim:
    def __init__(self, seed: int = 0):
        self.r = random.Random(seed)

    def eph(self) -> int:
        return self.r.randint(32768, 60999)

    # ---------------- benign -------------------------------------------------
    def http_session(self, t, client=None, server=None, label="BENIGN"):
        r = self.r
        c, s, sp, dp = client or r.choice(CLIENTS), server or r.choice(INTERNET + [SERVERS["web"]]), self.eph(), r.choice([443, 443, 443, 80])
        rtt = r.uniform(0.005, 0.08)
        out = [Packet(t, c, s, sp, dp, TCP, 60, "S", 0, label),
               Packet(t + rtt, s, c, dp, sp, TCP, 60, "SA", 0, label),
               Packet(t + rtt * 1.1, c, s, sp, dp, TCP, 52, "A", 0, label)]
        t += rtt * 1.2
        for _ in range(r.randint(1, 6)):
            req = r.randint(200, 900)
            out.append(Packet(t, c, s, sp, dp, TCP, req + 52, "PA", req, label)); t += rtt
            for _ in range(r.randint(2, 30)):
                size = r.choice([1448, 1448, 1448, r.randint(100, 1448)])
                out.append(Packet(t, s, c, dp, sp, TCP, size + 52, "A" if r.random() < .8 else "PA", size, label))
                t += r.uniform(0.0002, 0.004)
            out.append(Packet(t, c, s, sp, dp, TCP, 52, "A", 0, label)); t += r.uniform(0.05, 2.0)
        out += [Packet(t, c, s, sp, dp, TCP, 52, "FA", 0, label), Packet(t + rtt, s, c, dp, sp, TCP, 52, "FA", 0, label),
                Packet(t + rtt * 1.1, c, s, sp, dp, TCP, 52, "A", 0, label)]
        return out

    def dns_query(self, t, client=None, label="BENIGN", qlen=None):
        r = self.r
        c, sp = client or r.choice(CLIENTS), self.eph()
        q = qlen or r.randint(28, 60)
        return [Packet(t, c, SERVERS["dns"], sp, 53, UDP, q + 42, "", q, label),
                Packet(t + r.uniform(0.001, 0.03), SERVERS["dns"], c, 53, sp, UDP, q + 60 + 42, "", q + 60, label)]

    def ssh_session(self, t, label="BENIGN"):
        r = self.r
        c, s, sp = r.choice(CLIENTS), SERVERS["ssh"], self.eph()
        out = [Packet(t, c, s, sp, 22, TCP, 60, "S", 0, label), Packet(t + .002, s, c, 22, sp, TCP, 60, "SA", 0, label),
               Packet(t + .003, c, s, sp, 22, TCP, 52, "A", 0, label)]
        t += .004
        for _ in range(r.randint(40, 200)):  # interactive keystrokes + echoes
            out.append(Packet(t, c, s, sp, 22, TCP, 52 + 36, "PA", 36, label))
            out.append(Packet(t + .002, s, c, 22, sp, TCP, 52 + r.choice([36, 36, 100, 600]), "PA", 36, label))
            t += r.expovariate(3)
        out += [Packet(t, c, s, sp, 22, TCP, 52, "FA", 0, label), Packet(t + .002, s, c, 22, sp, TCP, 52, "FA", 0, label)]
        return out

    def db_query(self, t, label="BENIGN"):
        r = self.r
        c, s, sp = SERVERS["web"], SERVERS["db"], self.eph()
        out = [Packet(t, c, s, sp, 5432, TCP, 60, "S", 0, label), Packet(t + .0005, s, c, 5432, sp, TCP, 60, "SA", 0, label)]
        t += .001
        for _ in range(r.randint(1, 5)):
            out.append(Packet(t, c, s, sp, 5432, TCP, 52 + 120, "PA", 120, label))
            out.append(Packet(t + .002, s, c, 5432, sp, TCP, 52 + r.randint(80, 4000) % 1448, "PA", 200, label)); t += .01
        out.append(Packet(t, c, s, sp, 5432, TCP, 52, "FA", 0, label)); out.append(Packet(t + .001, s, c, 5432, sp, TCP, 52, "FA", 0, label))
        return out

    def ping(self, t, label="BENIGN"):
        c, s = self.r.choice(CLIENTS), self.r.choice(INTERNET)
        return [Packet(t + i, c, s, 0, 0, ICMP, 98, "", 56, label) for i in range(4)] + \
               [Packet(t + i + .02, s, c, 0, 0, ICMP, 98, "", 56, label) for i in range(4)]

    # ---- benign traffic that deliberately RESEMBLES attacks (hard negatives) ----
    def cloud_backup(self, t, label="BENIGN"):
        """Large legitimate upload (OneDrive/Drive sync) — looks like exfiltration."""
        r, c, s, sp = self.r, self.r.choice(CLIENTS), self.r.choice(INTERNET), self.eph()
        out = [Packet(t, c, s, sp, 443, TCP, 60, "S", 0, label), Packet(t + .02, s, c, 443, sp, TCP, 60, "SA", 0, label)]
        t += .03
        for _ in range(r.randint(200, 1800)):
            out.append(Packet(t, c, s, sp, 443, TCP, 1500, "A", 1448, label))
            if r.random() < .5:
                out.append(Packet(t + .001, s, c, 443, sp, TCP, 52 + (80 if r.random() < .05 else 0), "A", 0, label))
            t += r.uniform(0.001, 0.008)
        out += [Packet(t, c, s, sp, 443, TCP, 52, "FA", 0, label), Packet(t + .02, s, c, 443, sp, TCP, 52, "FA", 0, label)]
        return out

    def git_ssh(self, t, label="BENIGN"):
        """Short SSH session (git pull) — looks like one brute-force attempt."""
        r, c, s, sp = self.r, self.r.choice(CLIENTS), self.r.choice([SERVERS["ssh"]] + INTERNET), self.eph()
        out = [Packet(t, c, s, sp, 22, TCP, 60, "S", 0, label), Packet(t + .01, s, c, 22, sp, TCP, 60, "SA", 0, label),
               Packet(t + .02, c, s, sp, 22, TCP, 52, "A", 0, label)]
        tt = t + .03
        for size in (41, 1500, 48, 300, 84, 128, 96, *(r.choice([300, 1448, 600]) for _ in range(r.randint(0, 12)))):
            d = r.random() < .45
            out.append(Packet(tt, c if d else s, s if d else c, sp if d else 22, 22 if d else sp, TCP, 52 + size, "PA", size, label))
            tt += r.uniform(0.003, 0.04)
        out += [Packet(tt, c, s, sp, 22, TCP, 52, "FA", 0, label), Packet(tt + .01, s, c, 22, sp, TCP, 52, "FA", 0, label)]
        return out

    def refused(self, t, label="BENIGN"):
        """Connection to a closed port (misconfigured app) — looks like one scan probe."""
        c, s, sp, dp = self.r.choice(CLIENTS), self.r.choice(list(SERVERS.values())), self.eph(), self.r.choice([8080, 3000, 9200, 6379, 5000])
        return [Packet(t, c, s, sp, dp, TCP, 60, "S", 0, label), Packet(t + .0004, s, c, dp, sp, TCP, 54, "RA", 0, label)]

    def websocket(self, t, label="BENIGN"):
        """Long-lived keep-alive connection with tiny periodic frames — looks like Slowloris."""
        r, c, s, sp = self.r, self.r.choice(CLIENTS), self.r.choice(INTERNET + [SERVERS["web"]]), self.eph()
        out = [Packet(t, c, s, sp, 443, TCP, 60, "S", 0, label), Packet(t + .02, s, c, 443, sp, TCP, 60, "SA", 0, label),
               Packet(t + .03, c, s, sp, 443, TCP, 52 + 400, "PA", 400, label), Packet(t + .05, s, c, 443, sp, TCP, 52 + 200, "PA", 200, label)]
        for _ in range(r.randint(4, 12)):
            t += r.uniform(10, 30)
            out.append(Packet(t, c, s, sp, 443, TCP, 52 + r.choice([6, 6, 30, 120]), "PA", 6, label))
            out.append(Packet(t + .02, s, c, 443, sp, TCP, 52 + r.choice([6, 6, 60, 900]), "PA", 6, label))
        return out

    def long_dns(self, t, label="BENIGN"):
        """Legitimate long DNS names (CDN, DKIM/TXT lookups)."""
        return self.dns_query(t, label=label, qlen=self.r.randint(90, 190))

    # ---------------- attacks ------------------------------------------------
    def slow_scan(self, t):
        """Stealthy scan: few ports, seconds apart (evades simple rate rules)."""
        r, a, tgt, out = self.r, self.r.choice(ATTACKERS), self.r.choice(list(SERVERS.values())), []
        for port in r.sample(range(1, 1024), r.randint(30, 60)):
            sp = self.eph()
            out.append(Packet(t, a, tgt, sp, port, TCP, 58, "S", 0, "PortScan"))
            out.append(Packet(t + .0003, tgt, a, port, sp, TCP, 54, "RA", 0, "PortScan"))
            t += r.uniform(0.5, 3.0)
        return out

    def syn_flood(self, t, n=400):
        r, tgt, out = self.r, SERVERS["web"], []
        for _ in range(n):  # spoofed sources, SYN only, never completes handshake
            src = f"{r.randint(1, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"
            sp = self.eph()
            out.append(Packet(t, src, tgt, sp, 80, TCP, 60, "S", 0, "DoS-SYNFlood"))
            if r.random() < 0.5:
                out.append(Packet(t + .0005, tgt, src, 80, sp, TCP, 60, "SA", 0, "DoS-SYNFlood"))
            t += r.uniform(0.0001, 0.002)
        return out

    def port_scan(self, t):
        r, a, tgt, out = self.r, self.r.choice(ATTACKERS), self.r.choice(list(SERVERS.values())), []
        open_ports = {22, 80, 443, 53, 5432}
        for port in r.sample(range(1, 10000), 300) + list(open_ports):
            sp = self.eph()
            out.append(Packet(t, a, tgt, sp, port, TCP, 58, "S", 0, "PortScan"))
            out.append(Packet(t + .0003, tgt, a, port, sp, TCP, 58 if port in open_ports else 54, "SA" if port in open_ports else "RA", 0, "PortScan"))
            if port in open_ports:
                out.append(Packet(t + .0004, a, tgt, sp, port, TCP, 54, "R", 0, "PortScan"))
            t += r.uniform(0.0005, 0.01)
        return out

    def ssh_bruteforce(self, t, attempts=60):
        r, a, s, out = self.r, self.r.choice(ATTACKERS), SERVERS["ssh"], []
        for _ in range(attempts):
            sp = self.eph()
            out += [Packet(t, a, s, sp, 22, TCP, 60, "S", 0, "SSH-BruteForce"), Packet(t + .01, s, a, 22, sp, TCP, 60, "SA", 0, "SSH-BruteForce"),
                    Packet(t + .02, a, s, sp, 22, TCP, 52, "A", 0, "SSH-BruteForce")]
            tt = t + .03
            for size in (41, r.randint(900, 1500), 48, r.randint(200, 400), 84, *(r.choice([84, 96, 128]) for _ in range(r.randint(1, 4)))):  # banner, kex, auth tries
                d = r.random() < .5
                out.append(Packet(tt, a if d else s, s if d else a, sp if d else 22, 22 if d else sp, TCP, 52 + size, "PA", size, "SSH-BruteForce"))
                tt += r.uniform(0.005, 0.03)
            out += [Packet(tt, s, a, 22, sp, TCP, 52, "FA", 0, "SSH-BruteForce"), Packet(tt + .01, a, s, sp, 22, TCP, 52, "FA", 0, "SSH-BruteForce")]
            t += r.uniform(0.3, 1.2)
        return out

    def dns_tunnel(self, t, n=120):
        out = []
        c = self.r.choice(CLIENTS)
        for _ in range(n):  # long, high-entropy subdomains carrying data
            out += self.dns_query(t, c, "DNS-Tunneling", qlen=self.r.randint(180, 250))
            t += self.r.uniform(0.05, 0.3)
        return out

    def slowloris(self, t, conns=40):
        r, a, s, out = self.r, self.r.choice(ATTACKERS), SERVERS["web"], []
        for _ in range(conns):
            sp, tt = self.eph(), t + r.uniform(0, 2)
            out += [Packet(tt, a, s, sp, 80, TCP, 60, "S", 0, "Slowloris"), Packet(tt + .01, s, a, 80, sp, TCP, 60, "SA", 0, "Slowloris"),
                    Packet(tt + .02, a, s, sp, 80, TCP, 52, "A", 0, "Slowloris")]
            for k in range(r.randint(8, 14)):  # tiny partial headers every ~10 s
                tt += r.uniform(8, 12)
                out.append(Packet(tt, a, s, sp, 80, TCP, 52 + 12, "PA", 12, "Slowloris"))
                out.append(Packet(tt + .01, s, a, 80, sp, TCP, 52, "A", 0, "Slowloris"))
        return out

    def exfiltration(self, t):
        r, c, dst, sp = self.r, self.r.choice(CLIENTS), self.r.choice(ATTACKERS), self.eph()
        port = r.choice([443, 443, 8443, 4444, 21])
        out = [Packet(t, c, dst, sp, port, TCP, 60, "S", 0, "Exfiltration"), Packet(t + .05, dst, c, port, sp, TCP, 60, "SA", 0, "Exfiltration")]
        t += .06
        for _ in range(r.randint(1500, 4000)):  # large sustained upload, tiny ACKs back
            out.append(Packet(t, c, dst, sp, port, TCP, 1500, "A" if r.random() < .9 else "PA", 1448, "Exfiltration"))
            if r.random() < .35:
                out.append(Packet(t + .0005, dst, c, port, sp, TCP, 52, "A", 0, "Exfiltration"))
            t += r.uniform(0.0003, 0.002)
        out.append(Packet(t, c, dst, sp, port, TCP, 52, "FA", 0, "Exfiltration"))
        return out

    # ---------------- scenario ----------------------------------------------
    def scenario(self, duration: float = 600, benign_rate: float = 4.0, attacks: list[str] | None = None,
                 attack_count: int = 2, t0: float = 1_700_000_000.0) -> list[Packet]:
        r, pkts, t = self.r, [], t0
        gens = [(self.http_session, 52), (self.dns_query, 22), (self.db_query, 9), (self.ssh_session, 3), (self.ping, 5),
                (self.cloud_backup, 1.2), (self.git_ssh, 3), (self.refused, 2.5), (self.websocket, 1.5), (self.long_dns, 2)]
        while t < t0 + duration:
            g = r.choices([g for g, _ in gens], [w for _, w in gens])[0]
            pkts += g(t)
            t += r.expovariate(benign_rate)
        attack_fns = {"DoS-SYNFlood": self.syn_flood,
                      "PortScan": lambda t: self.port_scan(t) if self.r.random() < .6 else self.slow_scan(t), "SSH-BruteForce": self.ssh_bruteforce,
                      "DNS-Tunneling": self.dns_tunnel, "Slowloris": self.slowloris, "Exfiltration": self.exfiltration}
        for name in attacks if attacks is not None else ATTACK_TYPES:
            for _ in range(attack_count):
                pkts += attack_fns[name](t0 + r.uniform(0, duration * 0.8))
        pkts.sort(key=lambda p: p.ts)
        return pkts


def stream(seed=0, **kw) -> Iterator[Packet]:
    yield from Sim(seed).scenario(**kw)


def write_pcap(packets: list[Packet], path: str):
    """Write simulated packets to a real pcap (requires scapy)."""
    from scapy.all import ICMP as SICMP, IP, TCP as STCP, UDP as SUDP, Raw, wrpcap
    frames = []
    for p in packets:
        ip = IP(src=p.src, dst=p.dst)
        if p.proto == TCP:
            l4 = STCP(sport=p.sport, dport=p.dport, flags=p.flags or "A")
        elif p.proto == UDP:
            l4 = SUDP(sport=p.sport, dport=p.dport)
        else:
            l4 = SICMP()
        pkt = ip / l4 / Raw(b"x" * p.payload) if p.payload else ip / l4
        pkt.time = p.ts
        frames.append(pkt)
    wrpcap(path, frames)
