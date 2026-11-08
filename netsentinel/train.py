"""Train + evaluate NetSentinel.

    python -m netsentinel.train                        # simulated traffic (offline)
    python -m netsentinel.train --cicids MachineLearningCVE/   # CIC-IDS2017 CSV folder

Evaluation protocol (simulated data):
  * Train and test come from DIFFERENT simulation seeds (no flow leakage).
  * Experiment 1: multi-class detection of all 6 attack families.
  * Experiment 2: "zero-day" — one family is removed from training entirely;
    we measure how much of it the unsupervised Isolation Forest still catches.
"""
from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from .detector import MODEL_PATH, Detector, to_frame
from .flows import FEATURES, assemble
from .simulator import ATTACK_TYPES, Sim

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

CIC_MAP = {
    "Destination Port": "dst_port", "Protocol": "protocol", "Flow Duration": "duration",
    "Total Fwd Packets": "fwd_pkts", "Total Backward Packets": "bwd_pkts",
    "Total Length of Fwd Packets": "fwd_bytes", "Total Length of Bwd Packets": "bwd_bytes",
    "Packet Length Mean": "pkt_len_mean", "Packet Length Std": "pkt_len_std",
    "Max Packet Length": "pkt_len_max", "Min Packet Length": "pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean", "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Flow Bytes/s": "flow_bytes_s", "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "iat_mean", "Flow IAT Std": "iat_std", "Flow IAT Max": "iat_max", "Flow IAT Min": "iat_min",
    "SYN Flag Count": "syn_cnt", "FIN Flag Count": "fin_cnt", "RST Flag Count": "rst_cnt",
    "PSH Flag Count": "psh_cnt", "ACK Flag Count": "ack_cnt", "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "avg_payload",
}


def simulated(seeds, duration=900) -> tuple[pd.DataFrame, np.ndarray]:
    frames, labels = [], []
    for s in seeds:
        flows = list(assemble(Sim(s).scenario(duration=duration, attack_count=3)))
        frames.append(to_frame(flows)); labels += [f.label for f in flows]
    return pd.concat(frames, ignore_index=True), np.array(labels)


def load_cicids(folder: str, max_rows: int) -> tuple[pd.DataFrame, np.ndarray]:
    files = sorted(glob.glob(str(Path(folder) / "*.csv")))
    if not files:
        raise SystemExit(f"No CSV files in {folder}")
    df = pd.concat((pd.read_csv(f, low_memory=False) for f in files), ignore_index=True)
    df.columns = [c.strip() for c in df.columns]
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    if len(df) > max_rows:
        df = df.groupby("Label", group_keys=False).apply(lambda g: g.sample(min(len(g), max(2000, int(max_rows * len(g) / len(df)))), random_state=1))
    X = pd.DataFrame({dst: df[src] if src in df else 0 for src, dst in CIC_MAP.items()})
    X["duration"] = X["duration"] / 1e6  # CIC stores microseconds
    for col in FEATURES:
        if col not in X:
            X[col] = 0.0
    X["payload_bytes"] = X["fwd_bytes"] + X["bwd_bytes"]
    X["up_down_bytes_ratio"] = X["fwd_bytes"] / (X["bwd_bytes"] + 1.0)
    return X[FEATURES].astype(float), df["Label"].str.strip().str.replace("BENIGN", "BENIGN").values


def incident_test(det: Detector, attack: str, seeds=(300, 301, 302)) -> str:
    """End-to-end check: replay benign traffic + ONE instance of `attack` through
    the full streaming pipeline (classifier + anomaly + rules). Returns 'k/n'
    scenarios where any alert fired during the attack window."""
    hit = 0
    for sd in seeds:
        pkts = Sim(sd).scenario(duration=300, attacks=[attack], attack_count=1)
        atk = [p for p in pkts if p.label == attack]
        hosts = {p.src for p in atk} | {p.dst for p in atk}
        lo, hi = min(p.ts for p in atk) - 1, max(p.ts for p in atk) + 130
        # counts only alerts that involve the attack's own hosts — a random false alert doesn't count
        if any(a and lo <= a.ts <= hi and (a.dst in hosts and (a.src in hosts or a.src == "multiple")) for _, _, a in det.run(pkts)):
            hit += 1
    return f"{hit}/{len(seeds)}"


def false_alerts_per_hour(det: Detector, seeds=(400, 401)) -> float:
    n, secs = 0, 0
    for sd in seeds:
        pkts = Sim(sd).scenario(duration=900, attacks=[])
        n += sum(1 for _, _, a in det.run(pkts) if a); secs += 900
    return round(n / secs * 3600, 2)


def _cm_plot(cm, classes, path, title):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    cmn = cm / cm.sum(1, keepdims=True).clip(min=1)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.imshow(cmn, cmap="Blues", vmin=0, vmax=1)
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, str(v), ha="center", va="center", fontsize=8, color="white" if cmn[i, j] > .5 else "black")
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right"); ax.set_yticks(range(len(classes)), classes)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(title)
    fig.tight_layout(); fig.savefig(path, dpi=140); plt.close(fig)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cicids", help="folder with CIC-IDS2017 MachineLearningCVE CSVs")
    ap.add_argument("--max-rows", type=int, default=300_000)
    ap.add_argument("--skip-zero-day", action="store_true", help="skip the leave-one-attack-out experiment")
    args = ap.parse_args(argv)
    REPORTS.mkdir(exist_ok=True)

    if args.cicids:
        from sklearn.model_selection import train_test_split
        X, y = load_cicids(args.cicids, args.max_rows)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, stratify=y, random_state=1)
        source = "CIC-IDS2017"
    else:
        Xtr, ytr = simulated(range(1, 9))
        Xte, yte = simulated(range(100, 104))
        source = "simulated (train seeds 1-8, test seeds 100-103)"
    print(f"[data] {source}: train={len(Xtr)} flows, test={len(Xte)} flows")
    print(pd.Series(ytr).value_counts().to_string())

    # ---- Experiment 1: full model
    det = Detector().fit(Xtr, ytr)
    pred, conf, anom = det.predict(Xte)
    classes = sorted(set(ytr) | set(yte))
    rep = classification_report(yte, pred, labels=classes, output_dict=True, zero_division=0)
    print(classification_report(yte, pred, labels=classes, zero_division=0, digits=3))
    _cm_plot(confusion_matrix(yte, pred, labels=classes), classes, REPORTS / "confusion_matrix.png", "Flow classification (test)")
    benign = yte == "BENIGN"
    fpr_ml = float(((pred != "BENIGN") & benign).sum() / benign.sum())
    fpr_anom = float((anom & benign).sum() / benign.sum())

    imp = sorted(zip(FEATURES, det.clf.feature_importances_), key=lambda x: -x[1])[:12]
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.barh([n for n, _ in imp][::-1], [v for _, v in imp][::-1], color="#3b6ea5"); ax.set_title("Feature importance")
    fig.tight_layout(); fig.savefig(REPORTS / "feature_importance.png", dpi=140); plt.close(fig)

    # ---- Experiment 2: leave-one-attack-out ("zero-day") ----------------------
    # Each attack family is removed from training in turn; we measure how many of
    # its test flows are still flagged (by the anomaly layer or as another attack).
    zd = []
    if not args.skip_zero_day:
        for cls in [c for c in classes if c != "BENIGN"]:
            keep = ytr != cls
            det_zd = Detector().fit(Xtr[keep], ytr[keep])
            mask = yte == cls
            p2, _, a2 = det_zd.predict(Xte[mask])
            row = {"held_out_class": str(cls), "test_flows": int(mask.sum()),
                   "anomaly_detector": round(float(a2.mean()), 4),
                   "classifier_other_attack": round(float((p2 != "BENIGN").mean()), 4),
                   "total_flagged": round(float(((p2 != "BENIGN") | a2).mean()), 4)}
            row["incident_detected_full_pipeline"] = incident_test(det_zd, cls)
            zd.append(row); print(f"[zero-day] {row}")

    fa = false_alerts_per_hour(det)
    print(f"[false alerts] {fa} per hour on attack-free traffic")
    summary = {
        "dataset": source, "train_flows": int(len(Xtr)), "test_flows": int(len(Xte)),
        "macro_f1": round(f1_score(yte, pred, average="macro", zero_division=0), 4),
        "weighted_f1": round(f1_score(yte, pred, average="weighted", zero_division=0), 4),
        "benign_false_positive_rate_classifier": round(fpr_ml, 5),
        "benign_false_positive_rate_anomaly": round(fpr_anom, 5),
        "per_class": {k: {m: round(v, 4) for m, v in rep[k].items()} for k in classes if k in rep},
        "false_alerts_per_hour_benign_only": fa,
        "zero_day_experiment": zd,
        "top_features": [(n, round(float(v), 4)) for n, v in imp],
    }
    (REPORTS / "metrics.json").write_text(json.dumps(summary, indent=2))
    lines = ["| Class | Precision | Recall | F1 | Support |", "|---|---|---|---|---|"]
    for k in classes:
        r = rep[k]; lines.append(f"| {k} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1-score']:.3f} | {int(r['support'])} |")
    md = f"Dataset: {source}\n\n" + "\n".join(lines) + f"\n\nMacro F1: {summary['macro_f1']} · Benign FPR (classifier): {fpr_ml:.4%} · Benign FPR (anomaly): {fpr_anom:.4%}\n"
    if zd:
        md += ("\n### Leave-one-attack-out (zero-day simulation)\n\n"
               "| Unseen attack | Flows | Flagged by Isolation Forest | Flagged as other attack | Flow-level total | Incident detected by full pipeline (ML+anomaly+rules) |\n|---|---|---|---|---|---|\n")
        md += "\n".join(f"| {z['held_out_class']} | {z['test_flows']} | {z['anomaly_detector']:.1%} | {z['classifier_other_attack']:.1%} | {z['total_flagged']:.1%} | {z['incident_detected_full_pipeline']} |" for z in zd) + "\n"
    md += f"\nFalse alerts on attack-free traffic: {fa} per hour\n"
    (REPORTS / "metrics.md").write_text(md)
    det.save()
    print(f"[model] saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
