"""Alert suppressions — silence known-good activity without disabling rules.

Every network has expected "attacks": the IT vulnerability scanner, nightly
backups to the cloud, a monitoring system that pings everything. List them in
suppressions.yml (project root, or NETSENTINEL_SUPPRESSIONS=path):

    - attack: PortScan
      src: 10.0.0.50              # IP or CIDR
      reason: Nessus scanner, weekly scan
    - attack: Exfiltration
      src: 10.0.0.20
      dst: 203.0.113.0/24
      dport: 443
      reason: Nightly backup to S3
      expires: 2026-12-31         # optional, ISO date — stops applying after this day

Every field except `reason` is optional; an entry matches when all the fields
it does set match. Attack names are case-insensitive. Suppressed alerts are
counted, not silently lost.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "suppressions.yml"


def _net(value):
    if value in (None, ""):
        return None
    return ipaddress.ip_network(str(value).strip(), strict=False)


@dataclass
class Suppression:
    reason: str
    attack: str | None = None
    src: object = None
    dst: object = None
    dport: int | None = None
    expires: date | None = None
    hits: int = field(default=0, compare=False)

    @classmethod
    def from_dict(cls, d: dict) -> "Suppression":
        if not isinstance(d, dict):
            raise ValueError(f"suppression must be a mapping, got {d!r}")
        if not str(d.get("reason", "")).strip():
            raise ValueError(f"suppression needs a reason: {d}")
        unknown = set(d) - {"reason", "attack", "src", "dst", "dport", "expires"}
        if unknown:
            raise ValueError(f"unknown suppression field(s) {sorted(unknown)} in {d}")
        exp = d.get("expires")
        if exp is not None and not isinstance(exp, date):
            exp = date.fromisoformat(str(exp))
        return cls(
            reason=str(d["reason"]).strip(),
            attack=str(d["attack"]).lower() if d.get("attack") else None,
            src=_net(d.get("src")),
            dst=_net(d.get("dst")),
            dport=int(d["dport"]) if d.get("dport") not in (None, "") else None,
            expires=exp,
        )

    def active(self, today: date | None = None) -> bool:
        return self.expires is None or (today or date.today()) <= self.expires

    def matches(self, alert: dict, today: date | None = None) -> bool:
        if not self.active(today):
            return False
        if self.attack and str(alert.get("attack", "")).lower() != self.attack:
            return False
        for key, net in (("src", self.src), ("dst", self.dst)):
            if net is None:
                continue
            try:
                ip = ipaddress.ip_address(str(alert.get(key, "")))
            except ValueError:
                return False
            if ip.version != net.version or ip not in net:
                return False
        if self.dport is not None and alert.get("dport") != self.dport:
            return False
        return True

    def describe(self) -> dict:
        return {"reason": self.reason, "attack": self.attack, "src": str(self.src) if self.src else None,
                "dst": str(self.dst) if self.dst else None, "dport": self.dport,
                "expires": self.expires.isoformat() if self.expires else None,
                "active": self.active(), "hits": self.hits}


class Suppressor:
    def __init__(self, entries: list[Suppression] | None = None):
        self.entries = entries or []
        self.suppressed = 0

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Suppressor":
        path = path or os.getenv("NETSENTINEL_SUPPRESSIONS") or DEFAULT_FILE
        path = Path(path)
        if not path.exists():
            return cls([])
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        if not isinstance(data, list):
            raise ValueError(f"{path}: expected a list of suppressions")
        return cls([Suppression.from_dict(d) for d in data])

    def check(self, alert: dict) -> Suppression | None:
        """The matching suppression (and count it), or None if the alert should be raised."""
        for s in self.entries:
            if s.matches(alert):
                s.hits += 1
                self.suppressed += 1
                return s
        return None

    def filter(self, alerts: list[dict]) -> list[dict]:
        return [a for a in alerts if not self.check(a)]
