"""Hybrid detection engine.

Three layers run on every finished flow:

  1. Supervised  — Random Forest multi-class classifier (known attack families)
  2. Unsupervised — Isolation Forest trained on BENIGN flows only; flags flows
                    that look unlike normal traffic even if no known class fits
                    (zero-day / novel attacks)
  3. Rules       — sliding-window aggregate rules (rules.py)

Alerts from all layers are de-duplicated and mapped to MITRE ATT&CK.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .flows import FEATURES, Flow, Packet, assemble
from .rules import RuleEngine

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "netsentinel.joblib"

MITRE = {
    "DoS-SYNFlood": ("T1498.001", "Network Denial of Service: Direct Network Flood", "high"),
    "Slowloris": ("T1499.002", "Endpoint DoS: Service Exhaustion Flood", "high"),
    "PortScan": ("T1046", "Network Service Discovery", "medium"),
    "SSH-BruteForce": ("T1110.001", "Brute Force: Password Guessing", "high"),
    "DNS-Tunneling": ("T1071.004", "Application Layer Protocol: DNS", "high"),
    "Exfiltration": ("T1048", "Exfiltration Over Alternative Protocol", "critical"),
    "Anomaly": ("—", "Unknown anomalous behaviour (possible zero-day)", "medium"),
}


# Minimum number of flows of a class (from the same aggregation key, within
# EVIDENCE_WINDOW seconds) before an ML alert fires. Volume-type attacks are only
# meaningful in aggregate; one long DNS query or one refused SYN is normal.
MIN_EVIDENCE = {"DNS-Tunneling": 5, "PortScan": 5, "SSH-BruteForce": 3, "DoS-SYNFlood": 10}
EVIDENCE_WINDOW = 60.0


@dataclass
class Alert:
    ts: float
    attack: str
    severity: str
    src: str
    dst: str
    dport: int
    source: str            # "ml", "anomaly", "rule:<id>"
    confidence: float
    mitre_id: str
    mitre_name: str
    detail: str

    def to_dict(self):
        return asdict(self)


def to_frame(flows: Iterable[Flow]) -> pd.DataFrame:
    return pd.DataFrame([f.features() for f in flows], columns=FEATURES)


class Detector:
    def __init__(self, clf_threshold: float = 0.6, anomaly_quantile: float = 0.99):
        self.clf = RandomForestClassifier(n_estimators=250, min_samples_leaf=1, class_weight="balanced_subsample",
                                          n_jobs=-1, random_state=11)
        self.scaler = StandardScaler()
        self.iso = IsolationForest(n_estimators=300, max_samples=2048, contamination="auto", random_state=11)
        self.clf_threshold = clf_threshold
        self.anomaly_quantile = anomaly_quantile
        self.anomaly_cut = 0.0
        self.extreme_cut = 0.0
        self.anomaly_min_flows = 3      # anomalous flows between same hosts within anomaly_window
        self.anomaly_window = 120.0
        self.classes_: list[str] = []

    # ---------------------------------------------------------------- training
    def fit(self, X: pd.DataFrame, y: Iterable[str]):
        y = np.asarray(list(y))
        self.clf.fit(X, y)
        self.classes_ = list(self.clf.classes_)
        benign = X[y == "BENIGN"]
        Z = self.scaler.fit_transform(np.log1p(benign.clip(lower=0)))
        self.iso.fit(Z)
        # threshold = score below which only (1-q) of benign traffic falls -> controls false-positive rate
        scores = -self.iso.score_samples(Z)
        self.anomaly_cut = float(np.quantile(scores, self.anomaly_quantile))
        self.extreme_cut = float(scores.max() * 1.02)  # beyond anything seen in benign training data
        return self

    def anomaly_scores(self, X: pd.DataFrame) -> np.ndarray:
        return -self.iso.score_samples(self.scaler.transform(np.log1p(X.clip(lower=0))))

    def predict(self, X: pd.DataFrame, return_scores: bool = False):
        """Returns (label, confidence, anomaly_flag[, anomaly_score]) per flow."""
        proba = self.clf.predict_proba(X)
        idx = proba.argmax(1)
        labels = np.array(self.classes_)[idx]
        conf = proba.max(1)
        # low-confidence attack predictions fall back to BENIGN (reduces false positives)
        labels = np.where((labels != "BENIGN") & (conf < self.clf_threshold), "BENIGN", labels)
        sc = self.anomaly_scores(X)
        anom = (sc > self.anomaly_cut) & (labels == "BENIGN")
        return (labels, conf, anom, sc) if return_scores else (labels, conf, anom)

    # --------------------------------------------------------------- streaming
    def run(self, packets: Iterable[Packet], batch: int = 256, rules: RuleEngine | None = None,
            dedup_window: float = 60.0) -> Iterator[tuple[Flow, str, Alert | None]]:
        """Consume packets, yield (flow, predicted_label, alert_or_None)."""
        rules = rules or RuleEngine()
        recent: dict[tuple, float] = {}
        anom_hist: dict[tuple, list[float]] = {}
        evidence: dict[tuple, list[float]] = {}
        buf: list[Flow] = []

        def emit(alert: Alert) -> bool:
            k = (alert.attack, alert.src if alert.attack != "DoS-SYNFlood" else "*", alert.dst)
            if alert.ts - recent.get(k, -1e18) < dedup_window:
                return False
            recent[k] = alert.ts
            return True

        def drain() -> list:
            out: list = []
            if not buf:
                return out
            labels, conf, anom, scores = self.predict(to_frame(buf), return_scores=True)
            for f, lab, c, a, sc in zip(buf, labels, conf, anom, scores):
                alert = None
                for h in rules.observe(f):
                    m = MITRE[h.attack]
                    ra = Alert(h.ts, h.attack, h.severity, h.src, h.dst, f.dport, f"rule:{h.rule}", 1.0, m[0], m[1], h.detail)
                    if emit(ra):
                        alert = ra
                if alert is None and lab != "BENIGN":
                    key = (lab, f.dst) if lab == "DoS-SYNFlood" else (lab, f.src)
                    ev = [x for x in evidence.get(key, []) if f.start - x <= EVIDENCE_WINDOW] + [f.start]
                    evidence[key] = ev
                    if len(ev) >= MIN_EVIDENCE.get(lab, 1):
                        m = MITRE.get(lab, ("—", lab, "medium"))
                        ma = Alert(f.start, lab, m[2], f.src, f.dst, f.dport, "ml", round(float(c), 3), m[0], m[1],
                                   f"{len(ev)} flow(s) classified as {lab} in {int(EVIDENCE_WINDOW)}s "
                                   f"(latest: {len(f.fwd)}→/{len(f.bwd)}← pkts)")
                        if emit(ma):
                            alert = ma
                elif alert is None and a:
                    # Single anomalous flows are common (1% of benign by design), so an
                    # alert needs repetition between the same hosts, or one extreme outlier.
                    pair = tuple(sorted((f.src, f.dst)))
                    h = [x for x in anom_hist.get(pair, []) if f.start - x <= self.anomaly_window] + [f.start]
                    anom_hist[pair] = h
                    if len(h) >= self.anomaly_min_flows or sc > self.extreme_cut:
                        m = MITRE["Anomaly"]
                        why = "outlier far beyond benign profile" if sc > self.extreme_cut else f"{len(h)} anomalous flows in {int(self.anomaly_window)}s"
                        aa = Alert(f.start, "Anomaly", m[2], f.src, f.dst, f.dport, "anomaly", round(float(sc), 3), m[0], m[1],
                                   f"Deviates from learned benign profile ({why})")
                        if emit(aa):
                            alert = aa
                out.append((f, str(lab) if not a else "Anomaly", alert))
            buf.clear()
            return out

        for f in assemble(packets):
            buf.append(f)
            if len(buf) >= batch:
                yield from drain()
        yield from drain()

    # -------------------------------------------------------------- persistence
    def save(self, path: Path | str = MODEL_PATH):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path | str = MODEL_PATH) -> "Detector":
        return joblib.load(path)


def analyse_packets(det: Detector, packets: Iterable[Packet], rules: RuleEngine | None = None) -> dict:
    t = time.time()
    flows = alerts = 0
    out = []
    by_label: dict[str, int] = {}
    for f, lab, alert in det.run(packets, rules=rules):
        flows += 1
        by_label[lab] = by_label.get(lab, 0) + 1
        if alert:
            alerts += 1; out.append(alert.to_dict())
    return {"flows": flows, "alerts": out, "flow_labels": by_label, "seconds": round(time.time() - t, 2)}
