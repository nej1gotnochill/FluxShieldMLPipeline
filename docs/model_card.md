# Model Card — FluxShield DDoS-AT-2022 Detector

## Model purpose

A passive, per-flow DDoS attack detector for network capture analysis. Given a
bidirectional network flow summarized as 66 numeric features, the model outputs
a calibrated probability that the flow belongs to an attack class and a binary
verdict at operating threshold t = 0.5.

## Intended use

- Research and education in leakage-aware network-intrusion-detection ML.
- Offline analysis of captured traffic (PCAP → flows → per-flow verdicts).
- Near-real-time triage on flow tables: batch throughput ≈ 481,000 flows/s;
  single-record median latency 49.8 ms (p95 60.4 ms) with the calibrated
  300-tree ensemble (5.3 MB artifact).
- Early-window decisions: a causal 1 s / 3 s / 5 s evaluation exists
  (`src/early_detection.py`); 3 s windows match full-flow recall (0.9979).

## Out-of-scope use

- **Not a production security appliance.** This is a research/prototype model.
  It provides no guarantee against arbitrary or novel network attacks.
- Not trained for encrypted-traffic content inspection, malware reverse
  engineering, or host-based intrusion detection.
- Not validated on datasets other than DDoS-AT-2022; cross-dataset transfer is
  untested.
- Deployment on live links would additionally require the missing operational
  pieces (flow export, TTL/state management, alerting, drift monitoring), which
  are outside this repository's scope.

## Training data

- **Dataset:** DDoS-AT-2022 (Canadian Institute for Cybersecurity,
  Atlantic Technological University) — 45 classic PCAP captures, 37.84 GB,
  98,658,747 packets, 11 attack families + benign traffic.
- **Extracted flows:** 1,236,285 bidirectional flows (19,276 benign / 1,217,009
  attack at flow level — a 1.6 % / 98.4 % split that is the inverse of the
  packet-level balance).
- **Splits:** capture-disjoint throughout. Final test = untouched contiguous
  May 3–6 block (17 captures, 448,076 flows). Development = 28 earlier
  captures. Track B holdout = all development captures of tcp_syn_flood,
  tcp_rst, and udp_flood.
- Raw PCAPs are intentionally NOT distributed with this repository.

## Features

66 numeric features (all float32), fully documented with exact definitions,
units, and ONLINE/TERMINAL availability in `reports/feature_dictionary.md`:
directional packet/byte counts, per-direction and pooled packet-length
statistics, full/forward/backward inter-arrival-time statistics, 12 TCP flag
counters, header bytes, ratios, TCP window sizes, active/idle period
statistics, and rates.

Leakage policy: IP addresses, ports, timestamps, capture identifiers, and
labels are metadata only — never predictive features.

## Model architecture

```
ExtraTreesClassifier(
    n_estimators=300, max_depth=20, min_samples_leaf=1,
    max_features="sqrt", class_weight="balanced",
    criterion="gini", random_state=42)
```

Selected as tuning trial `4fc1eda5-ex-019` from 57 randomized trials over
capture-disjoint folds (the RandomForest arm was early-stopped with a
documented rationale when its search surface proved flat).

## Calibration

Sigmoid (Platt) calibration via `CalibratedClassifierCV(cv="prefit")`, fitted
on held-out fold-5 validation captures. Isotonic was rejected after a measured
degeneracy check: it collapsed to 3–4 distinct outputs on the near-separable
calibration fold, destroying threshold resolution (Brier 0.000013, ECE 0.000028
for sigmoid).

## Threshold

t = 0.5 (frozen). Highest-recall threshold meeting the development FPR ≤ 1e-3
target (held-out dev-benign FPR 0.00085), inside the flat F1 plateau (0.3–0.7),
and at the ceiling imposed by never-seen-family probability mass (median ≈ 0.62
on Track B holdouts — higher thresholds sacrifice unseen-family recall).

## Evaluation protocol

No random flow-level splitting anywhere (capture/session leakage risk):
- **A1:** strict chronological expanding walk-forward (windows are
  single-class by dataset construction; reported with caveats).
- **A2:** capture-disjoint stratified GroupKFold (k=5), both classes per fold.
- **Track B:** attack-family holdout (never-seen families).
- **Final test:** contiguous May 3–6 two-class block, touched exactly once
  after all fitting/calibration/threshold decisions were frozen.

Details: `docs/evaluation_protocol.md`.

## Performance (final untouched test, measured once)

448,076 flows / 17 captures:

| Metric | Value |
|---|---:|
| Precision | 0.999998 |
| Recall | 0.997849 |
| F1 | 0.998922 |
| FPR | 0.00018 (1 / 5,555 benign) |
| FNR | 0.00215 (952 / 442,521 attacks) |
| PR-AUC | 1.0000 |
| ROC-AUC | 1.0000 |

Confusion matrix: TN 5,554 · FP 1 · FN 952 · TP 441,569.
Per-attack-family recall ≥ 0.997 (worst: flash_traffic 0.9970).

Track B family-holdout recall (aggregate 0.9740): tcp_syn_flood 1.0000,
tcp_rst 0.9918, udp_flood 0.9594.

Early-window recall: 1 s 0.6816 (F1 0.8106, FPR 0.00288); 3 s 0.9979 (F1
0.9989, FPR 0.00198); 5 s 0.9979 (F1 0.9989, FPR 0.00198).

## Known limitations

- 31,243 exact duplicate feature rows exist dataset-wide (2.5 %; 16,709 in
  development, 2.12 %). A matched-partition sensitivity analysis showed metric
  changes ≤ 1e-6 (frozen model) and 0.0007 recall (5-fold retrain) — duplicates
  do not materially drive the results, but absolute numbers should be read with
  this in mind.
- tcp_syn_flood and tcp_rst are single-capture families: they can never appear
  in both training and test captures within Track A; only Track B measures them
  as unseen families.
- The dataset is class-segregated in time (attacks Mar–Apr/May 4–6, benign
  concentrated May 3); strictly chronological validation windows are therefore
  single-class by construction (A1 caveat).
- Final-test benign volume is modest (5,555 flows): FPR estimates carry
  granularity of roughly ±0.0002.

## Dataset bias / distribution shift

- Benign captures are heterogeneous: A1 measured FPR on unseen IDP benign of
  0.9997 before any of that benign pattern entered training, dropping to
  0.0006 after — a distribution-shift artifact, not a model property.
- Attack traffic comes from scripted tools; identical packet patterns produce
  identical flows (the duplicate rows above) and sibling families share near-
  identical feature vectors (documented in the data-validation report).
- All captures originate from one laboratory testbed; field traffic may differ.

## Failure modes (measured, `reports/error_analysis_report.md`)

- 98.6 % of the 952 final-test false negatives are one-packet flows, where
  insufficient temporal evidence limits discriminability.
- Residual FNs are long (380–1,020 s), low-rate (≈ 0.10 pkt/s) flows inside the
  benign support of training.
- The single false positive is a long, low-rate benign flow resembling the
  slow-attack manifold.
- 1 s windows fail on pacing-revealed attacks (http_slow_header recall 0.12,
  http_slow_body 0.15) because inter-packet evidence has not accumulated yet;
  all families recover by 3 s.

## Reproducibility

- Seed 42 everywhere; every experiment's raw records are preserved
  (`experiments/`, `experiments/research/`).
- Frozen artifacts: `models/calibrated_model.joblib`, `feature_schema.json`,
  `model_metadata.json`, `threshold.json` (unchanged since final evaluation;
  integrity verified by SHA-256).
- Tests: `pytest -q` → 16 passed.
- Rebuild path from raw data: see README § Reproduction.

## Ethical / security considerations

- This model is a research prototype for traffic analysis; it must not be used
  as the sole basis for blocking, throttling, or attributing traffic, and not
  as a guarantee of protection against arbitrary attacks.
- Flow features are derived from traffic metadata; the pipeline never needs
  payload content. Operators remain responsible for privacy compliance of any
  capture they analyze.
- The family-holdout evaluation demonstrates behavioral generalization to
  attack families excluded from training; it does not establish guaranteed
  detection of arbitrary zero-day attacks.
