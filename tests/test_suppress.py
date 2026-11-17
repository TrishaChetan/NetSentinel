from datetime import date

import pytest
from fastapi.testclient import TestClient

from netsentinel import api
from netsentinel.detector import analyse_packets
from netsentinel.simulator import Sim, write_pcap
from netsentinel.suppress import Suppression, Suppressor

ALERT = {"attack": "PortScan", "src": "10.0.0.50", "dst": "10.0.0.7", "dport": 22}


def test_entry_matches_all_set_fields():
    s = Suppression.from_dict({"attack": "portscan", "src": "10.0.0.0/24", "reason": "scanner"})
    assert s.matches(ALERT)
    assert not s.matches({**ALERT, "src": "10.0.1.50"})
    assert not s.matches({**ALERT, "attack": "SSH-BruteForce"})


def test_dport_and_dst():
    s = Suppression.from_dict({"dst": "10.0.0.7", "dport": 22, "reason": "jump host"})
    assert s.matches(ALERT)
    assert not s.matches({**ALERT, "dport": 2222})


def test_expiry():
    s = Suppression.from_dict({"src": "10.0.0.50", "reason": "pentest", "expires": "2026-01-31"})
    assert s.matches(ALERT, today=date(2026, 1, 31))
    assert not s.matches(ALERT, today=date(2026, 2, 1))


def test_ipv6_alert_does_not_match_ipv4_rule():
    s = Suppression.from_dict({"src": "10.0.0.0/8", "reason": "x"})
    assert not s.matches({**ALERT, "src": "fe80::1"})


@pytest.mark.parametrize("bad", [{"src": "10.0.0.1"}, {"reason": "x", "srcc": "1.2.3.4"}, {"reason": "x", "src": "nope"}])
def test_bad_entries_rejected(bad):
    with pytest.raises(ValueError):
        Suppression.from_dict(bad)


def test_load_and_count(tmp_path):
    f = tmp_path / "s.yml"
    f.write_text("- attack: PortScan\n  src: 10.0.0.50\n  reason: scanner\n")
    sup = Suppressor.load(f)
    assert sup.filter([ALERT, {**ALERT, "src": "10.9.9.9"}]) == [{**ALERT, "src": "10.9.9.9"}]
    assert sup.suppressed == 1 and sup.entries[0].hits == 1
    assert Suppressor.load(tmp_path / "missing.yml").entries == []


def test_analyse_packets_suppresses(detector):
    pkts = Sim(62).scenario(duration=60, attacks=["PortScan"], attack_count=1)
    raw = analyse_packets(detector, pkts)
    assert any(a["attack"] == "PortScan" for a in raw["alerts"])
    sup = Suppressor([Suppression.from_dict({"attack": "PortScan", "reason": "scanner"})])
    r = analyse_packets(detector, pkts, suppressor=sup)
    assert not any(a["attack"] == "PortScan" for a in r["alerts"])
    assert r["suppressed"] >= 1


def test_api_skips_suppressed(detector, tmp_path, monkeypatch):
    pcap = tmp_path / "t.pcap"
    write_pcap(Sim(62).scenario(duration=60, attacks=["PortScan"], attack_count=1), str(pcap))
    monkeypatch.setattr(api, "get_detector", lambda: detector)
    monkeypatch.setattr(api, "suppressor",
                        Suppressor([Suppression.from_dict({"attack": "PortScan", "reason": "scanner"})]))
    api.store.clear()
    c = TestClient(api.app)
    r = c.post("/api/pcap", files={"file": ("t.pcap", pcap.read_bytes())}).json()
    assert r["suppressed"] >= 1
    assert not any(a["attack"] == "PortScan" for a in c.get("/api/alerts").json())
    info = c.get("/api/suppressions").json()
    assert info["entries"][0]["reason"] == "scanner" and info["entries"][0]["hits"] >= 1
