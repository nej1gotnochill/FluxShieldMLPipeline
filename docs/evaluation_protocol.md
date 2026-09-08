# Evaluation Protocol

All evaluation in FluxShield is **capture-disjoint**: every split unit is a
complete PCAP capture, never an individual flow. This document specifies each
track, the reasoning, and the known limitations.

## Why not random flow-level splitting?

Flows within one capture share capture conditions: identical tooling, timing,
source/destination landscape, link conditions, and lab environment. A random
flow-level split places sibling flows from the same capture (often near-
identical feature vectors — scripted attack tools emit byte-identical packets)
on both sides of the split, so the model is validated on effectively seen
data. This inflates metrics and masks the hard problem: recognizing an attack
pattern in a *capture* the model has never observed. All primary evaluation
therefore groups by capture.

## Track A1 — strict chronological walk-forward

Captures are ordered by first-packet timestamp. Training windows expand
strictly forward in time:

| Fold | Train (captures) | Validation (captures) |
|---|---|---|
| 1 | indices 0–8 (Mar 17–29) | indices 9–13 (Apr 1) |
| 2 | indices 0–13 (+ Apr) | indices 14–21 (May 3, first 8) |
| 3 | indices 0–21 (→ May 3, 8) | indices 22–27 (May 3, next 6) |

**Known limitation — class-segregated chronology.** The dataset's attack
captures cluster in Mar 17–Apr 1 and May 4–6, benign captures on May 3 (plus
one early benign capture). Strictly chronological validation windows are
therefore single-class by construction (fold 1: attack-only; folds 2–3:
benign-only), so PR-AUC/ROC-AUC are undefined in those windows and FPR/recall
are reported separately. A1 measures temporal robustness, not balanced
detection; it also exposed the distribution-shift finding: FPR on unseen
IDP-benign captures was 0.9997 before any of that benign pattern entered
training and 0.0006 after — a property of the dataset's benign heterogeneity,
not of a specific model.

## Track A2 — capture-disjoint GroupKFold (primary development track)

`StratifiedGroupKFold(k=5, shuffle=True)` over capture groups (seed 42, with a
seeded-reshuffle search ensuring every fold contains both classes; fallback to
permuted-rank GroupKFold documented in `src/train.py`). Every flow's group key
is its capture file, so no capture appears in both a fold's train and
validation sides. Used for baseline model comparison, the 57-trial
hyperparameter search, and the research ablations (all ablation configs share
one identical partition so feature-set differences are isolated).

## Track B — attack-family holdout (generalization)

Entire attack families are removed from training and reserved for evaluation:

- `tcp_syn_flood` (1 capture — entirely held out)
- `tcp_rst` (1 capture — entirely held out)
- `udp_flood` (all development captures of the family held out)

Training uses the remaining development captures; the held-out captures never
appear in training. This measures **behavioral generalization** to unseen
attack mechanics (spoofed SYN floods without handshakes, RST-based attacks,
UDP amplification/floods). Measured aggregate holdout recall 0.9740
(tcp_syn_flood 1.0000, tcp_rst 0.9918, udp_flood 0.9594). The family-holdout
evaluation demonstrates behavioral generalization to attack families excluded
from training; it does not establish guaranteed detection of arbitrary
zero-day attacks.

Note: single-capture families (tcp_syn_flood, tcp_rst) can never appear in
both training and test within Track A; Track B is the only track that scores
them as unseen.

## Final test — untouched contiguous May 3–6 two-class block

- Composition: 17 captures (indices 28–44 chronologically) = the 2 latest
  May-3 benign captures + all 15 May 4–6 attack captures — 448,076 flows.
- Design constraint honored: the chronologically latest block (May 4–6 alone)
  is attack-only, which cannot measure FPR; extending to the contiguous May
  3–6 two-class block (user-approved design change) preserves both
  untouched-ness and measurable FPR.
- Access discipline: excluded from feature selection, hyperparameter tuning,
  threshold selection, calibration, and model selection. Scored **exactly
  once**, after the model, calibrator, and threshold were frozen.
- Result (measured, unchanged since): Precision 0.999998 · Recall 0.997849 ·
  F1 0.998922 · FPR 0.00018 · FNR 0.00215 · PR-AUC 1.0000 · ROC-AUC 1.0000 ·
  TN 5,554 / FP 1 / FN 952 / TP 441,569.

## Leakage controls (verified, not assumed)

- Preprocessing, feature selection, oversampling/weights: fitted on training
  data only, inside sklearn Pipelines.
- IPs/ports/timestamps/capture ids: metadata-only, asserted non-features by
  `src/data_validation.py`.
- Duplicate handling across splits: duplicates occur within captures; splits
  are capture-disjoint, so no duplicate bridges splits (sensitivity analyzed
  separately in `reports/duplicate_sensitivity_report.md`).
- The split manifest (`reports/split_manifest.csv/.json`) is machine-verified:
  exactly one role per capture per track, no overlap, final test disjoint.
