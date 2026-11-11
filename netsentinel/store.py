"""SQLite alert store (thread-safe, zero-config)."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, attack TEXT, severity TEXT, src TEXT, dst TEXT, dport INTEGER,
  source TEXT, confidence REAL, mitre_id TEXT, mitre_name TEXT, detail TEXT,
  status TEXT DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS stats (k TEXT PRIMARY KEY, v REAL);
"""
COLS = ["ts", "attack", "severity", "src", "dst", "dport", "source", "confidence", "mitre_id", "mitre_name", "detail"]


class AlertStore:
    def __init__(self, path: str | Path = ":memory:"):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def add(self, alert: dict) -> int:
        with self.lock:
            cur = self.db.execute(f"INSERT INTO alerts ({','.join(COLS)}) VALUES ({','.join('?' * len(COLS))})",
                                  [alert[c] for c in COLS])
            self.db.commit()
            return cur.lastrowid

    def bump(self, key: str, n: float = 1):
        with self.lock:
            self.db.execute("INSERT INTO stats(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=v+excluded.v", (key, n))
            self.db.commit()

    def stats(self) -> dict:
        with self.lock:
            s = {r["k"]: r["v"] for r in self.db.execute("SELECT k, v FROM stats")}
            s["by_attack"] = {r[0]: r[1] for r in self.db.execute("SELECT attack, COUNT(*) FROM alerts GROUP BY attack")}
            s["by_severity"] = {r[0]: r[1] for r in self.db.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")}
            s["top_sources"] = [dict(r) for r in self.db.execute(
                "SELECT src, COUNT(*) AS n FROM alerts GROUP BY src ORDER BY n DESC LIMIT 5")]
            return s

    def list(self, since_id: int = 0, limit: int = 200) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(
                "SELECT * FROM alerts WHERE id > ? ORDER BY id DESC LIMIT ?", (since_id, limit))]

    def all(self) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute("SELECT * FROM alerts ORDER BY id")]

    def set_status(self, alert_id: int, status: str) -> bool:
        with self.lock:
            cur = self.db.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
            self.db.commit()
            return cur.rowcount == 1

    def clear(self):
        with self.lock:
            self.db.executescript("DELETE FROM alerts; DELETE FROM stats;")
            self.db.commit()
