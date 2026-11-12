"""Push alerts to a webhook — Slack, Discord, Microsoft Teams or any HTTP endpoint.

    export NETSENTINEL_WEBHOOK_URL=https://hooks.slack.com/services/...
    export NETSENTINEL_WEBHOOK_MIN_SEVERITY=high      # default: high

The payload works for all common chat tools at once: Slack reads "text",
Discord reads "content", Teams (incoming webhook) reads "text", and generic
receivers get the full alert under "alert".

Sending happens on a background thread with a short timeout, so a slow or
broken webhook never stalls packet processing. Uses only the standard library.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.request
from datetime import datetime, timezone

from .export import SEVERITY_ORDER

SEV_EMOJI = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def format_message(a: dict) -> str:
    sev = str(a.get("severity", "")).lower()
    when = datetime.fromtimestamp(float(a.get("ts", 0)), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    port = f":{a['dport']}" if a.get("dport") else ""
    return (f"{SEV_EMOJI.get(sev, '⚪')} *NetSentinel {sev.upper()}* — {a.get('attack')}\n"
            f"{a.get('src')} → {a.get('dst')}{port}  ·  {a.get('mitre_id')} {a.get('mitre_name')}\n"
            f"{a.get('detail', '')}\n"
            f"_{when} · source: {a.get('source')} · confidence {float(a.get('confidence') or 0):.0%}_")


def build_payload(a: dict) -> dict:
    text = format_message(a)
    return {"text": text, "content": text[:2000], "alert": a}


class WebhookNotifier:
    def __init__(self, url: str | None = None, min_severity: str | None = None, timeout: float = 5.0):
        self.url = url if url is not None else os.getenv("NETSENTINEL_WEBHOOK_URL", "")
        sev = (min_severity or os.getenv("NETSENTINEL_WEBHOOK_MIN_SEVERITY", "high")).lower()
        if sev not in SEVERITY_ORDER:
            raise ValueError(f"min severity must be one of {', '.join(SEVERITY_ORDER)}")
        self.min_level = SEVERITY_ORDER[sev]
        self.timeout = timeout
        self.sent = 0
        self.failed = 0

    @property
    def enabled(self) -> bool:
        return bool(self.url)

    def wants(self, a: dict) -> bool:
        return self.enabled and SEVERITY_ORDER.get(str(a.get("severity", "")).lower(), 0) >= self.min_level

    def _post(self, a: dict) -> bool:
        req = urllib.request.Request(
            self.url, data=json.dumps(build_payload(a), default=str).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "NetSentinel"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                ok = 200 <= r.status < 300
        except Exception as e:  # never let notifications break detection
            print(f"[netsentinel] webhook failed: {e}")
            ok = False
        if ok:
            self.sent += 1
        else:
            self.failed += 1
        return ok

    def notify(self, a: dict, block: bool = False) -> bool:
        """Send if the alert meets the severity floor. Returns True if queued/sent."""
        if not self.wants(a):
            return False
        if block:
            return self._post(a)
        threading.Thread(target=self._post, args=(a,), daemon=True).start()
        return True
