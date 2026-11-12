import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from netsentinel import api
from netsentinel.notify import WebhookNotifier, build_payload
from netsentinel.store import AlertStore

ALERT = {"ts": 1700000000, "attack": "PortScan", "severity": "high", "src": "10.0.0.5", "dst": "10.0.0.9",
         "dport": 22, "source": "rule:scan", "confidence": 0.9, "mitre_id": "T1046",
         "mitre_name": "Network Service Discovery", "detail": "40 ports in 10s"}


@pytest.fixture
def receiver():
    got = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/hook", got
    srv.shutdown()


def test_payload_works_for_slack_and_discord():
    p = build_payload(ALERT)
    assert "PortScan" in p["text"] and "10.0.0.5 → 10.0.0.9:22" in p["text"]
    assert p["content"] == p["text"]
    assert p["alert"]["mitre_id"] == "T1046"


def test_severity_floor(receiver):
    url, got = receiver
    n = WebhookNotifier(url, "high")
    assert n.notify(ALERT, block=True)
    assert not n.notify({**ALERT, "severity": "medium"}, block=True)
    assert len(got) == 1 and n.sent == 1


def test_disabled_and_broken_url():
    assert not WebhookNotifier("", "low").notify(ALERT, block=True)
    n = WebhookNotifier("http://127.0.0.1:9/nothing", "low", timeout=1)
    assert n.notify(ALERT, block=True) is False and n.failed == 1   # no exception raised
    with pytest.raises(ValueError):
        WebhookNotifier("x", "urgent")


def test_api_records_and_notifies(receiver, monkeypatch):
    url, got = receiver
    monkeypatch.setattr(api, "store", AlertStore())
    monkeypatch.setattr(api, "notifier", WebhookNotifier(url, "high"))
    api.record_alert({**ALERT, "severity": "critical"})
    api.notifier.notify(ALERT, block=True)
    client = TestClient(api.app)
    assert client.post("/api/webhook/test").json() == {"sent": True}
    status = client.get("/api/webhook").json()
    assert status["enabled"] and status["min_severity"] == "high"
    assert len(api.store.all()) == 1
