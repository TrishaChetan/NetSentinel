"""Export alerts for a SIEM or a spreadsheet.

Two formats:
  * csv   — one row per alert, opens in Excel / Google Sheets
  * jsonl — JSON Lines (one alert per line) with an ISO-8601 "@timestamp",
            the format Elastic/Filebeat, Splunk and Wazuh ingest directly
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
FORMATS = ("csv", "jsonl")
FIELDS = ["id", "@timestamp", "severity", "attack", "src", "dst", "dport", "source",
          "confidence", "mitre_id", "mitre_name", "detail", "status"]


def iso(ts) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return ""


def filter_alerts(alerts, min_severity: str | None = None, status: str | None = None) -> list[dict]:
    if min_severity and min_severity not in SEVERITY_ORDER:
        raise ValueError(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    floor = SEVERITY_ORDER.get(min_severity or "low", 0)
    out = []
    for a in alerts:
        if SEVERITY_ORDER.get(str(a.get("severity", "")).lower(), 0) < floor:
            continue
        if status and a.get("status", "open") != status:
            continue
        out.append(a)
    return out


def _record(a: dict) -> dict:
    r = {k: a.get(k) for k in FIELDS if k != "@timestamp"}
    r["@timestamp"] = iso(a.get("ts"))
    r["status"] = a.get("status", "open")
    r["event"] = {"kind": "alert", "module": "netsentinel"}
    if r.get("id") is None:  # alerts from a pcap analysis aren't stored, so have no id
        r.pop("id")
    return r


def to_jsonl(alerts) -> str:
    return "".join(json.dumps(_record(a), default=str) + "\n" for a in alerts)


def to_csv(alerts) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    for a in alerts:
        w.writerow(_record(a))
    return buf.getvalue()


def render(alerts, fmt: str) -> str:
    if fmt not in FORMATS:
        raise ValueError(f"format must be one of {', '.join(FORMATS)}")
    return to_csv(alerts) if fmt == "csv" else to_jsonl(alerts)


def format_from_path(path: str) -> str:
    return "csv" if path.lower().endswith(".csv") else "jsonl"
