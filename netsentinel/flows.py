"""Packet -> bidirectional flow assembly and CICFlowMeter-style feature extraction.

A flow is identified by the 5-tuple (src, dst, sport, dport, proto), direction-
normalised so that request and response packets land in the same flow. A flow
ends on FIN/RST, after an idle timeout, or after an active timeout. The feature
set mirrors a subset of CIC-IDS2017 so models can be trained on that dataset.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Iterable, Iterator

TCP, UDP, ICMP = 6, 17, 1


@dataclass(slots=True)
class Packet:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    length: int
    flags: str = ""        # TCP flags, e.g. "S", "SA", "A", "PA", "FA", "R"
    payload: int = 0       # payload bytes
    label: str = "BENIGN"  # ground truth (simulator only)


FEATURES = [
    "dst_port", "protocol", "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
    "pkt_len_mean", "pkt_len_std", "pkt_len_max", "pkt_len_min",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_bytes_s", "flow_pkts_s",
    "iat_mean", "iat_std", "iat_max", "iat_min",
    "syn_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "ack_cnt",
    "down_up_ratio", "up_down_bytes_ratio", "payload_bytes", "avg_payload", "zero_payload_ratio",
]


@dataclass
class Flow:
    key: tuple
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    start: float
    last: float
    fwd: list[Packet] = field(default_factory=list)
    bwd: list[Packet] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)
    closed: bool = False

    def add(self, p: Packet):
        (self.fwd if p.src == self.src and p.sport == self.sport else self.bwd).append(p)
        self.last = p.ts
        self.labels[p.label] = self.labels.get(p.label, 0) + 1
        if "F" in p.flags or "R" in p.flags:
            fins = sum("F" in x.flags for x in self.fwd + self.bwd)
            if "R" in p.flags or fins >= 2:
                self.closed = True

    @property
    def label(self) -> str:
        attacks = {k: v for k, v in self.labels.items() if k != "BENIGN"}
        return max(attacks, key=attacks.get) if attacks else "BENIGN"

    def features(self) -> dict[str, float]:
        pkts = sorted(self.fwd + self.bwd, key=lambda p: p.ts)
        lens = [p.length for p in pkts]
        iats = [b.ts - a.ts for a, b in zip(pkts, pkts[1:])] or [0.0]
        dur = max(self.last - self.start, 1e-6)
        fb, bb = sum(p.length for p in self.fwd), sum(p.length for p in self.bwd)
        payloads = [p.payload for p in pkts]
        flag = lambda c: sum(c in p.flags for p in pkts)  # noqa: E731
        return {
            "dst_port": self.dport,
            "protocol": self.proto,
            "duration": dur,
            "fwd_pkts": len(self.fwd),
            "bwd_pkts": len(self.bwd),
            "fwd_bytes": fb,
            "bwd_bytes": bb,
            "pkt_len_mean": statistics.fmean(lens),
            "pkt_len_std": statistics.pstdev(lens) if len(lens) > 1 else 0.0,
            "pkt_len_max": max(lens),
            "pkt_len_min": min(lens),
            "fwd_pkt_len_mean": fb / len(self.fwd) if self.fwd else 0.0,
            "bwd_pkt_len_mean": bb / len(self.bwd) if self.bwd else 0.0,
            "flow_bytes_s": (fb + bb) / dur,
            "flow_pkts_s": len(pkts) / dur,
            "iat_mean": statistics.fmean(iats),
            "iat_std": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
            "iat_max": max(iats),
            "iat_min": min(iats),
            "syn_cnt": flag("S"),
            "fin_cnt": flag("F"),
            "rst_cnt": flag("R"),
            "psh_cnt": flag("P"),
            "ack_cnt": flag("A"),
            "down_up_ratio": len(self.bwd) / max(1, len(self.fwd)),
            "up_down_bytes_ratio": fb / (bb + 1.0),
            "payload_bytes": sum(payloads),
            "avg_payload": statistics.fmean(payloads),
            "zero_payload_ratio": sum(x == 0 for x in payloads) / len(payloads),
        }

    def summary(self) -> dict:
        return {"src": self.src, "dst": self.dst, "sport": self.sport, "dport": self.dport,
                "proto": self.proto, "start": self.start, "end": self.last,
                "packets": len(self.fwd) + len(self.bwd)}


class FlowAssembler:
    def __init__(self, idle_timeout: float = 30.0, active_timeout: float = 120.0):
        self.idle, self.active = idle_timeout, active_timeout
        self.table: dict[tuple, Flow] = {}
        self.time_wait: dict[tuple, float] = {}   # recently closed keys -> close time

    @staticmethod
    def _key(p: Packet) -> tuple:
        a, b = (p.src, p.sport), (p.dst, p.dport)
        return (*min(a, b), *max(a, b), p.proto)

    def push(self, p: Packet) -> list[Flow]:
        """Add a packet; return any flows that finished as a result."""
        done = []
        k = self._key(p)
        # TIME_WAIT: trailing ACK/FIN of a just-closed TCP connection belongs to the
        # old flow, not a new one (a new connection on the same 5-tuple starts with SYN)
        tw = self.time_wait.get(k)
        if tw is not None:
            if p.ts - tw < 5.0 and "S" not in p.flags:
                return done
            del self.time_wait[k]
        f = self.table.get(k)
        if f and (p.ts - f.last > self.idle or p.ts - f.start > self.active):
            done.append(self.table.pop(k)); f = None
        if f is None:
            f = Flow(k, p.src, p.dst, p.sport, p.dport, p.proto, p.ts, p.ts)
            self.table[k] = f
        f.add(p)
        if f.closed:
            done.append(self.table.pop(k))
            if p.proto == TCP:
                self.time_wait[k] = p.ts
        return done

    def expire(self, now: float) -> list[Flow]:
        stale = [k for k, f in self.table.items() if now - f.last > self.idle]
        self.time_wait = {k: t for k, t in self.time_wait.items() if now - t < 5.0}
        return [self.table.pop(k) for k in stale]

    def flush(self) -> list[Flow]:
        out = list(self.table.values()); self.table.clear(); return out


def assemble(packets: Iterable[Packet], **kw) -> Iterator[Flow]:
    fa = FlowAssembler(**kw)
    last_expire = None
    for p in packets:
        yield from fa.push(p)
        if last_expire is None or p.ts - last_expire > 5:
            yield from fa.expire(p.ts); last_expire = p.ts
    yield from fa.flush()
