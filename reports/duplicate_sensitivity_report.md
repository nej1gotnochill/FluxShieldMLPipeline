# Analysis 1 — Exact-Duplicate Sensitivity (DEVELOPMENT DATA ONLY)

**Date:** 2026-09-09 · **Scope:** development captures only (28) · **Final test:** untouched, never loaded here · **Frozen artifacts:** unchanged
**Raw outputs:** `experiments/research/dup_sensitivity_results.csv`, `dup_sensitivity_S2_{full,dedup}_folds.csv`, `dup_rows_by_family.csv` · machine-readable: `reports/duplicate_sensitivity_results.json` · seed 42 · sklearn 1.5.0 / numpy 2.5.2 / pandas 2.2.2

## 1. Duplicate accounting

| Quantity | Value |
|---|---:|
| Original development rows | 788,209 |
| Exact duplicate feature rows (removed, keep-first) | **16,709** |
| Deduplicated development rows | 771,500 |
| Duplicate percentage (dev) | **2.12 %** |

The previously reported dataset-wide figure was 31,243 (2.5 % of all 45 captures); the remainder (~14.5 k) lies in the final-test block. Duplicates concentrate in scripted flood captures — see `dup_rows_by_family.csv` (physically real: attack tools emitting byte-identical packets produce identical flow features; not corruption).

## 2. S1 — Frozen model evaluated on full vs deduplicated dev table

The untouched `models/calibrated_model.joblib` scored both tables at the frozen t=0.5. Valid as a sensitivity probe: no fitting, no selection, official results untouched.

| Metric | Full dev | Dedup dev | Δ (abs) |
|---|---:|---:|---:|
| Recall | 0.9999974 | 0.9999974 | −0.0000000 |
| Precision | 0.9999987 | 0.9999987 | −0.0000000 |
| F1 | 0.9999981 | 0.9999980 | −0.0000000 |
| FPR | 0.0000729 | 0.0000729 | +0.0000000 |
| FNR | 0.0000026 | 0.0000026 | +0.0000000 |
| PR-AUC | 1.0000000 | 1.0000000 | <1e-7 |
| ROC-AUC | 0.9999999 | 0.9999999 | <1e-7 |

**Every difference is ≤ 1e-6 — indistinguishable from zero.**

## 3. S2 — Frozen-config retrain, full vs deduplicated training data

A separate experimental model (the exact ex-019 ExtraTrees configuration) retrained inside the capture-disjoint A-2 folds on full vs deduplicated training rows. **Methodological fix applied:** folds were built ONCE as capture partitions and shared by both arms — rebuilding folds per arm converges on different reshuffle seeds and moves the benign distribution-shift fold (FPR 0.85, documented artifact) between positions, which would masquerade as a dedup effect.

| Metric (5-fold mean) | Full | Dedup | Δ (abs) |
|---|---:|---:|---:|
| Recall | 0.999682 | 0.998974 | **−0.000707** |
| Precision | 0.994340 | 0.994293 | −0.000047 |
| F1 | 0.996970 | 0.996592 | −0.000379 |
| FNR | 0.000318 | 0.001026 | +0.000707 |
| PR-AUC | 1.000000 | 0.999993 | −0.000007 |
| ROC-AUC | 0.999994 | 0.999797 | −0.000197 |

The mean FPR (~0.170) in both arms is dominated by the one fold holding the IDP benign distribution-shift captures; it is **identical in both arms** (7633 FP full vs 7633 FP dedup in that fold) and therefore cancels from the comparison.

## 4. Conclusion

**The strong results do not depend materially on exact duplicates.** Removing all 16,709 duplicate dev rows changes frozen-model metrics by ≤ 1e-6 and 5-fold retrain recall by 0.0007 (one part in 1,400). Duplicates mildly reinforce training signal for scripted floods but are not load-bearing for the reported performance. **No threat to the frozen model's validity.**
