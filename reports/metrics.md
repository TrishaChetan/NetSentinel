Dataset: simulated (train seeds 1-8, test seeds 100-103)

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.999 | 0.998 | 0.999 | 14600 |
| DNS-Tunneling | 0.983 | 0.987 | 0.985 | 1437 |
| DoS-SYNFlood | 1.000 | 1.000 | 1.000 | 4800 |
| Exfiltration | 1.000 | 1.000 | 1.000 | 12 |
| PortScan | 1.000 | 1.000 | 1.000 | 2373 |
| SSH-BruteForce | 1.000 | 1.000 | 1.000 | 720 |
| Slowloris | 1.000 | 0.998 | 0.999 | 644 |

Macro F1: 0.9976 · Benign FPR (classifier): 0.1644% · Benign FPR (anomaly): 1.0205%

### Leave-one-attack-out (zero-day simulation)

| Unseen attack | Flows | Flagged by Isolation Forest | Flagged as other attack | Flow-level total | Incident detected by full pipeline (ML+anomaly+rules) |
|---|---|---|---|---|---|
| DNS-Tunneling | 1437 | 0.1% | 0.0% | 0.1% | 3/3 |
| DoS-SYNFlood | 4800 | 50.2% | 0.0% | 50.2% | 3/3 |
| Exfiltration | 12 | 100.0% | 0.0% | 100.0% | 3/3 |
| PortScan | 2373 | 0.9% | 0.0% | 0.9% | 3/3 |
| SSH-BruteForce | 720 | 0.0% | 0.0% | 0.0% | 3/3 |
| Slowloris | 644 | 90.4% | 0.2% | 90.5% | 3/3 |

False alerts on attack-free traffic: 0.0 per hour
