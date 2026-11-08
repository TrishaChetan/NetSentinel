from fastapi.testclient import TestClient

from netsentinel import api
from netsentinel.detector import analyse_packets
from netsentinel.simulator import ATTACK_TYPES, Sim, write_pcap


def test_classifier_accuracy(detector):
    from netsentinel.train import simulated
    X, y = simulated([50], duration=300)
    pred, _, _ = detector.predict(X)
    assert (pred == y).mean() > 0.97


def test_every_attack_raises_alert(detector):
    pkts = Sim(60).scenario(duration=300, attacks=ATTACK_TYPES, attack_count=1)
    found = {a["attack"] for a in analyse_packets(detector, pkts)["alerts"]}
    assert set(ATTACK_TYPES) <= found, found


def test_no_alerts_on_benign(detector):
    r = analyse_packets(detector, Sim(61).scenario(duration=300, attacks=[]))
    assert r["alerts"] == [], r["alerts"]


def test_pcap_upload_api(detector, tmp_path):
    pcap = tmp_path / "t.pcap"
    write_pcap(Sim(62).scenario(duration=60, attacks=["PortScan"], attack_count=1), str(pcap))
    api.get_detector = lambda: detector  # inject test model
    api.store.clear()
    c = TestClient(api.app)
    r = c.post("/api/pcap", files={"file": ("t.pcap", pcap.read_bytes())}).json()
    assert any(a["attack"] == "PortScan" for a in r["alerts"])
    alerts = c.get("/api/alerts").json()
    assert alerts and c.patch(f"/api/alerts/{alerts[0]['id']}", json={"status": "resolved"}).json()["ok"]
    assert c.get("/api/stats").json()["by_attack"]["PortScan"] >= 1
    assert "NetSentinel" in c.get("/").text
