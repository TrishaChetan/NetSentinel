# Project Report Outline — NetSentinel

## Abstract
Signature-based intrusion detection cannot recognise new attacks, while purely anomaly-based detection produces too many false
alarms to be usable. This project presents NetSentinel, a hybrid network IDS combining a Random Forest classifier, an Isolation
Forest trained only on benign traffic, and window-based correlation rules. On held-out traffic it reaches a macro F1 of [0.998],
detects every attack family in a leave-one-attack-out zero-day experiment, and raises [0] false alerts per hour on attack-free
traffic. [Add CIC-IDS2017 results here.]

## 1. Introduction
- Motivation: growth of network attacks; limits of signature IDS (Snort/Suricata) and of anomaly IDS
- Objectives: detect known + unknown attacks, low false-alarm rate, explainable alerts mapped to MITRE ATT&CK
- Scope: flow-level analysis (no payload inspection)

## 2. Literature survey
- Signature IDS: Snort, Suricata, Zeek
- ML IDS on KDD'99 / NSL-KDD / CIC-IDS2017 / UNSW-NB15 (Random Forest, SVM, deep learning)
- Anomaly detection: Isolation Forest, autoencoders, one-class SVM
- Known issues: dataset bias, high false-positive rates, poor generalisation to unseen attacks
- Gap addressed: layered detection with an explicit zero-day evaluation and alert-level (not just flow-level) metrics

## 3. System design
- Architecture diagram and layer responsibilities (README, docs/ARCHITECTURE.md)
- Flow model and feature list
- Rule definitions R1–R5 and MITRE mapping

## 4. Implementation
- Python, Scapy, scikit-learn, FastAPI, SQLite
- Traffic simulator design, including hard negatives (cloud backup vs exfiltration, git-over-SSH vs brute force…)
- Hyper-parameters: RF 250 trees, balanced class weights, confidence threshold 0.6; IF 300 trees, 2048 samples, 99th-percentile cut-off

## 5. Results
- Experiment 1: per-class precision/recall/F1 + confusion matrix
- Experiment 2: leave-one-attack-out table — discuss *why* the anomaly layer catches some families and not others
- Experiment 3: false alerts per hour; show the improvement from alert aggregation (214/h → 0/h)
- CIC-IDS2017 results
- Dashboard screenshots during the live demo

## 6. Conclusion & future work
- TLS/JA3 fingerprinting, deep-learning sequence models, Zeek integration, distributed sensors, automatic threshold tuning

## References
[datasets, papers, MITRE ATT&CK]
