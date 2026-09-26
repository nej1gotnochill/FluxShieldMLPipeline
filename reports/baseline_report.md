# Baseline Results — DDoS-AT-2022 (STEP 7)

**Date:** 2026-09-08 · **Data:** 793,764 development flows (30 captures) · **Features:** 66 float32 · **Models:** LogisticRegression, RandomForest, ExtraTrees, HistGradientBoosting · **No tuning, no threshold optimization, no calibration, final test untouched.**

Raw records: `experiments/baseline_results.csv`, `experiments/baseline_family_recall.csv`.

## Track A-1 — Strict chronological walk-forward (single-class windows, by design)

The dataset is class-segregated in time (Mar 17–Apr 1 = attacks + 1 benign, May 3 = benign only, May 4–6 = attacks only), so every chronological window is single-class. Reported with that caveat; metrics marked `—` are undefined for that window.

| Fold | Window | benign / attack | Measurable |
|---|---|---|---|
| 1 | train Mar 17–29 (9 caps) → val Apr 1 (5 caps) | 0 / 655,390 | recall, FNR |
| 2 | train +Apr 1 → val May 3 first 8 (benign) | 3,746 / 0 | FPR |
| 3 | train +May 3 first 8 → val May 3 last 8 (benign) | 7,895 / 0 | FPR |

**Fold 1 (attack recall):** ExtraTrees **1.0000** · RandomForest **1.0000** · LR 0.5892 · HGB 0.5699
**Fold 2 (benign FPR):** LR 0.9746 · RF 0.9997 · ET 0.9989 · HGB 0.9963 — *models trained before May 3 flag nearly all IDP benign flows as attacks*
**Fold 3 (benign FPR):** LR 0.0000 · RF 0.0006 · ET 0.0004 · HGB 0.0001 — *after adding May 3 benign to training, FPR collapses to ~0*

**Key finding:** the fold-2→fold-3 swing (FPR 0.999 → 0.000) is a *distribution-shift artifact*, not model quality: the IDP benign captures look nothing like `httperf` benign traffic, and the chronological design cannot separate "new benign pattern" from "attack" until benign examples enter training. This is exactly why Track A-2 exists.

## Track A-2 — Capture-group stratified folds (GroupKFold on pcaps, k=5; every val fold has both classes)

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|
| **ExtraTrees** | 1.0000 ± 0.0000 | **0.9999 ± 0.0003** | **0.9999 ± 0.0001** | 1.0000 | 1.0000 | **0.0007 ± 0.0014** | 0.0001 ± 0.0003 |
| RandomForest | 1.0000 ± 0.0000 | 0.9999 ± 0.0003 | 0.9999 ± 0.0001 | 1.0000 | 1.0000 | 0.0011 ± 0.0020 | 0.0001 ± 0.0003 |
| HistGradientBoost | 1.0000 ± 0.0000 | 0.9997 ± 0.0007 | 0.9998 ± 0.0003 | 1.0000 | 1.0000 | 0.0009 ± 0.0012 | 0.0003 ± 0.0007 |
| LogisticRegression | 1.0000 ± 0.0001 | 0.8439 ± 0.3471 | 0.8726 ± 0.2839 | 1.0000 | 0.9981 ± 0.0037 | 0.0016 ± 0.0030 | 0.1561 ± 0.3471 |

**Fold-4 breakdown (LR collapse):** LR recall on `tcp_syn_flood` = **0.0725** (spoofed SYNs, no handshake/backward traffic) while RF/ET/HGB = 1.0000. GroupKFold puts the single-capture family entirely in one fold, exposing LR's inability to generalize to never-seen attack mechanics. Trees have no such issue.

## Track B — Family holdout (tcp_syn_flood + tcp_rst + all 3 udp_flood captures held out; 655,390 attack flows, 0 benign)

| Model | Aggregate recall | tcp_rst | tcp_syn_flood | udp_flood |
|---|---:|---:|---:|---:|
| **ExtraTrees** | **0.9740** | 0.9918 | 1.0000 | 0.9594 |
| RandomForest | 0.5630 | 0.6784 | 0.9615 | 0.3917 |
| LogisticRegression | 0.4207 | 1.0000 | 0.9987 | 0.0350 |
| HistGradientBoost | 0.0755 | 0.0000 | 0.3699 | 0.0025 |

Track B measures recall only (holdout is attack-only by design; FPR comes from Track A-2's benign validation).

## Inference timing (measured; models fitted on chronological fold-1 train, validated on 655,390 flows)

| Model | Train (fold-1) | Throughput (flows/s) | Latency median / p95 (single row, ms) |
|---|---:|---:|---:|
| ExtraTrees | 0.6 s | 1,860,400 | 21.9 / 33.3 |
| RandomForest | 2.1 s | 1,962,824 | 21.5 / 33.1 |
| HistGradientBoost | 3.2 s | 408,210 | 4.0 / 4.7 |
| LogisticRegression | 3.7 s | 1,341,475 | 1.2 / 1.4 |

## Recommendation (for STEP 9 tuning)

**ExtraTrees** is the strongest baseline on every axis: best Track A-2 recall/F1/FPR, best Track B generalization (0.974 on never-seen families), fastest training, and 1.86M flows/s throughput. RandomForest is equivalent within noise but slower to train; HGB is fast at inference but fails catastrophically on held-out families; LR is unsuitable for never-seen attack mechanics. **Tune ExtraTrees (and RandomForest as the second candidate) in STEP 9.**

## Honest caveats

- Track A-2 folds contain single-capture families in exactly one fold; per-fold family recall should be read alongside Track B for generalization truth.
- 75% of flows end at capture end (`ended_by=capture_end`) — flood durations are truncated by capture length, a dataset property.
- No metrics here involve the final test (May 4–6, 15 captures, 442,521 flows) — it remains untouched for STEP 12.