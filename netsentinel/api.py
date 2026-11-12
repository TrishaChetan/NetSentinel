"""NetSentinel web service: live dashboard, pcap upload, alert triage API.

    uvicorn netsentinel.api:app --reload   -> http://127.0.0.1:8000
"""
from __future__ import annotations

import tempfile
import threading
import time
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from .capture import read_pcap
from .detector import MODEL_PATH, Detector, analyse_packets
from .export import FORMATS, SEVERITY_ORDER, filter_alerts, render
from .notify import WebhookNotifier
from .simulator import ATTACK_TYPES, Sim
from .store import AlertStore

app = FastAPI(title="NetSentinel", version="1.0.0", description="Hybrid ML network intrusion detection")
store = AlertStore(Path(tempfile.gettempdir()) / "netsentinel_alerts.db")
notifier = WebhookNotifier()  # no-op unless NETSENTINEL_WEBHOOK_URL is set

SAMPLE_ALERT = {"ts": 0, "attack": "Test alert", "severity": "critical", "src": "10.0.0.5", "dst": "203.0.113.9",
                "dport": 443, "source": "test", "confidence": 1.0, "mitre_id": "T0000", "mitre_name": "Webhook test",
                "detail": "If you can read this, NetSentinel notifications are working."}


def record_alert(a: dict) -> None:
    """Store an alert and push it to the webhook if it's severe enough."""
    store.add(a)
    notifier.notify(a)
TEMPLATE = Path(__file__).parent / "templates" / "dashboard.html"
_demo = {"running": False, "thread": None}


@lru_cache(maxsize=1)
def get_detector() -> Detector:
    if not MODEL_PATH.exists():
        raise HTTPException(503, "Model not trained. Run: python -m netsentinel.train")
    return Detector.load()


class DemoRequest(BaseModel):
    duration: int = 300
    attacks: list[str] = ATTACK_TYPES
    speed: float = 30.0   # replay speed-up factor
    seed: int = 7


class StatusUpdate(BaseModel):
    status: str  # open | investigating | resolved | false_positive


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return TEMPLATE.read_text(encoding="utf-8")


@app.get("/api/alerts")
def alerts(since_id: int = 0, limit: int = 200):
    return store.list(since_id, min(limit, 1000))


@app.get("/api/stats")
def stats():
    return store.stats() | {"demo_running": _demo["running"]}


@app.get("/api/alerts/export")
def export_alerts(format: str = "jsonl", min_severity: str | None = None, status: str | None = None):
    """Download alerts as CSV or JSON Lines (SIEM-ready), optionally filtered."""
    if format not in FORMATS:
        raise HTTPException(400, f"format must be one of {', '.join(FORMATS)}")
    try:
        rows = filter_alerts(store.all(), min_severity, status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    media = "text/csv" if format == "csv" else "application/x-ndjson"
    name = f"netsentinel-alerts-{time.strftime('%Y%m%d-%H%M%S')}.{format}"
    return Response(render(rows, format), media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.get("/api/webhook")
def webhook_status():
    level = next(k for k, v in SEVERITY_ORDER.items() if v == notifier.min_level)
    return {"enabled": notifier.enabled, "min_severity": level, "sent": notifier.sent, "failed": notifier.failed}


@app.post("/api/webhook/test")
def webhook_test():
    """Send a sample critical alert to check the webhook configuration."""
    if not notifier.enabled:
        raise HTTPException(400, "Set NETSENTINEL_WEBHOOK_URL to enable notifications")
    ok = notifier.notify({**SAMPLE_ALERT, "ts": time.time()}, block=True)
    if not ok:
        raise HTTPException(502, "Webhook did not accept the test message — check the URL")
    return {"sent": True}


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, body: StatusUpdate):
    if body.status not in {"open", "investigating", "resolved", "false_positive"}:
        raise HTTPException(400, "bad status")
    if not store.set_status(alert_id, body.status):
        raise HTTPException(404, "alert not found")
    return {"ok": True}


@app.post("/api/pcap")
async def upload_pcap(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > 200 * 1024 * 1024:
        raise HTTPException(413, "pcap too large (200 MB max)")
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(data)
    try:
        result = analyse_packets(get_detector(), read_pcap(tmp.name))
    except Exception as e:  # malformed capture
        raise HTTPException(400, f"could not parse pcap: {e}") from e
    finally:
        Path(tmp.name).unlink(missing_ok=True)
    for a in result["alerts"]:
        record_alert(a)
    store.bump("flows", result["flows"])
    return result


def _replay(req: DemoRequest):
    det = get_detector()
    pkts = Sim(req.seed).scenario(duration=req.duration, attacks=[a for a in req.attacks if a in ATTACK_TYPES], attack_count=1)
    t0, wall0 = pkts[0].ts, time.time()
    for flow, label, alert in det.run(pkts, batch=32):
        if not _demo["running"]:
            break
        lag = (flow.last - t0) / req.speed - (time.time() - wall0)   # pace replay to (sim time / speed)
        if lag > 0:
            time.sleep(min(lag, 2))
        store.bump("flows")
        store.bump("packets", len(flow.fwd) + len(flow.bwd))
        store.bump("bytes", sum(p.length for p in flow.fwd + flow.bwd))
        if alert:
            record_alert(alert.to_dict())
    _demo["running"] = False


@app.post("/api/demo/start")
def demo_start(req: DemoRequest = DemoRequest()):
    if _demo["running"]:
        return {"ok": False, "msg": "already running"}
    get_detector()
    store.clear()
    _demo["running"] = True
    _demo["thread"] = threading.Thread(target=_replay, args=(req,), daemon=True)
    _demo["thread"].start()
    return {"ok": True}


@app.post("/api/demo/stop")
def demo_stop():
    _demo["running"] = False
    return {"ok": True}


@app.post("/api/reset")
def reset():
    store.clear()
    return {"ok": True}
