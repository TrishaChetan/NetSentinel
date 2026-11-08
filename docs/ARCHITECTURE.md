# NetSentinel — Design Notes

## Why three layers?

| Layer | Strength | Blind spot |
|---|---|---|
| Random Forest (supervised) | High precision on attack families it was trained on | Cannot recognise an attack type it never saw |
| Isolation Forest (unsupervised) | Flags flows unlike anything in the benign baseline → novel attacks | Misses attacks built from many *normal-looking* flows; ~1% of benign flows look unusual |
| Window rules | Sees aggregate behaviour (one source, hundreds of ports) | Needs hand-tuned thresholds; only covers known patterns |

The leave-one-attack-out experiment in the README quantifies this: each layer alone has gaps, together they detected every unseen family.

## Flow assembly

* Key: direction-normalised 5-tuple `(min(endpoint), max(endpoint), proto)` so both directions share a flow.
* Flow ends on RST, on the second FIN, after 30 s idle or after 120 s active (long connections are split, like CICFlowMeter).
* **TIME_WAIT**: for 5 s after a TCP flow closes, non-SYN packets on the same key are absorbed. Without this, every final ACK created a junk one-packet flow (found by the unit tests).

## Features (29)

Destination port, protocol, duration, forward/backward packet and byte counts, packet-length statistics (mean, std, min, max, per direction), byte and packet rates, inter-arrival-time statistics, TCP flag counts (SYN, FIN, RST, PSH, ACK), down/up packet ratio, up/down **byte** ratio, payload totals and zero-payload ratio.

The up/down byte ratio was added after the first zero-day experiment: without it, exfiltration (large one-way upload) scored inside the benign range.

## Alert manager

1. **Evidence thresholds** — volume-type classes need several flows from the same source (or to the same target for floods) within 60 s: DNS tunnelling 5, port scan 5, brute force 3, SYN flood 10. One long DNS name or one refused connection is normal; fifty are not.
2. **Anomaly aggregation** — an anomaly alert needs 3 anomalous flows between the same hosts in 120 s, or one flow scoring beyond anything seen in benign training data.
3. **De-duplication** — the same (attack, source, destination) can't re-alert within 60 s; rules have a 120 s cooldown.

This took the false-alert rate on attack-free traffic from 214/hour (first version) to 0/hour without losing any incident detections.

## Exfiltration rule (R5) — destination rarity

A single exfiltration flow looks statistically similar to a legitimate cloud backup (both are large one-way uploads over 443). What differs is *who else talks to that destination*. R5 tracks, for every external IP, how many internal hosts have contacted it, and fires when a host uploads ≥1 MB with an up/down ratio ≥10 to a destination contacted by ≤2 internal hosts. This mirrors "rare destination" analytics used in UEBA/DLP products. `HOME_NET` (RFC 1918 by default) defines what "internal" means, like Snort's `$HOME_NET`.

## Service hardening

* Upload limit 200 MB; malformed pcaps return HTTP 400 instead of crashing.
* Dashboard escapes all values (IP fields come from attacker-controlled packets).
* Docker image runs as a non-root user; live sniffing is kept in the CLI so the web service never needs raw-socket privileges.
