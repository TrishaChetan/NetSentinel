import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from netsentinel import api
from netsentinel.export import filter_alerts, render
from netsentinel.store import AlertStore

ALERTS = [
    {"ts": 1700000000, "attack": "port_scan", "severity": "medium", "src": "10.0.0.5", "dst": "10.0.0.9",
     "dport": 22, "source": "rule", "confidence": 0.9, "mitre_id": "T1046", "mitre_name": "Network Service Discovery",
     "detail": "scan, 40 ports", "status": "open"},
    {"ts": 1700000060, "attack": "dns_tunnel", "severity": "critical", "src": "10.0.0.7", "dst": "8.8.8.8",
     "dport": 53, "source": "ml", "confidence": 0.97, "mitre_id": "T1071.004", "mitre_name": "DNS",
     "detail": "long queries", "status": "resolved"},
]


def test_filters():
    assert [a["attack"] for a in filter_alerts(ALERTS, "high")] == ["dns_tunnel"]
    assert [a["attack"] for a in filter_alerts(ALERTS, status="open")] == ["port_scan"]
    with pytest.raises(ValueError):
        filter_alerts(ALERTS, "urgent")


def test_jsonl_is_siem_shaped():
    lines = render(ALERTS, "jsonl").splitlines()
    rec = json.loads(lines[0])
    assert len(lines) == 2
    assert rec["@timestamp"].startswith("2023-11-14T22:13:20")
    assert rec["event"] == {"kind": "alert", "module": "netsentinel"}


def test_csv_round_trip():
    rows = list(csv.DictReader(io.StringIO(render(ALERTS, "csv"))))
    assert rows[1]["mitre_id"] == "T1071.004"
    assert "," in rows[0]["detail"]  # commas in fields are quoted correctly


def test_api_export(monkeypatch):
    store = AlertStore()
    for a in ALERTS:
        store.add(a)
    monkeypatch.setattr(api, "store", store)
    client = TestClient(api.app)
    r = client.get("/api/alerts/export", params={"format": "csv", "min_severity": "critical"})
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert r.text.count("\n") == 2  # header + 1 alert
    assert client.get("/api/alerts/export", params={"format": "xml"}).status_code == 400
