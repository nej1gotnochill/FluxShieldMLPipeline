# Analysis 4 — Threshold / Operational Cost Sensitivity (DEVELOPMENT ONLY)

**Date:** 2026-09-09 · **Data:** development calibration split (fold-5 construction, identical to `src/calibrate.py`: 614,531 fit / 173,678 calibration flows, capture-disjoint) · **Model:** the frozen calibrated artifact applied as-is (no refitting — the calibration captures are held out from fold-5's train window, so probabilities are honest out-of-sample) · **`threshold.json` untouched; final test never loaded.**
**Raw outputs:** `experiments/research/threshold_sensitivity_results.csv` · machine-readable: `reports/threshold_sensitivity_results.json` · seed 42

## 1. Grid results (calibration split: 172,496 attack / 1,182 benign flows)

NOTE: benign count is small (1,182) in this fold — FPR estimates are correspondingly coarse (±1 FP ≈ ±0.00085). The fold-5 validation captures are attack-dominated; broader benign FPR estimates at t=0.5 were measured in the calibration step over all dev benign (8/19,276 = 0.00042).

| t | Precision | Recall | F1 | FPR | FNR | FP | FN |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.05 | 0.99988 | 0.99999 | 0.99994 | 0.01777 | 0.00001 | 21 | 1 |
| 0.10 | 0.99997 | 0.99999 | 0.99998 | 0.00508 | 0.00001 | 6 | 1 |
| 0.20 | 0.99998 | 0.99999 | 0.99999 | 0.00338 | 0.00001 | 4 | 1 |
| 0.30 | 0.99999 | 0.99999 | 0.99999 | 0.00169 | 0.00001 | 2 | 2 |
| 0.40 | 0.99999 | 0.99999 | 0.99999 | 0.00169 | 0.00001 | 2 | 2 |
| **0.50 (deployed)** | **0.99999** | **0.99999** | **0.99999** | **0.00085** | **0.00001** | **1** | **2** |
| 0.60 | 1.00000 | 0.99999 | 0.99999 | 0.00000 | 0.00001 | 0 | 2 |
| 0.70 | 1.00000 | 0.99999 | 0.99999 | 0.00000 | 0.00001 | 0 | 2 |
| 0.80 | 1.00000 | 0.99998 | 0.99999 | 0.00000 | 0.00002 | 0 | 3 |
| 0.90 | 1.00000 | 0.99998 | 0.99999 | 0.00000 | 0.00002 | 0 | 3 |
| 0.95 | 1.00000 | 0.99998 | 0.99999 | 0.00000 | 0.00002 | 0 | 3 |

## 2. Reference points

| Point | Value |
|---|---|
| Threshold achieving FPR ≤ 1e-3 | **t = 0.5 is the highest-recall such threshold** (FPR 0.00085, recall 0.99999) — also every t ≥ 0.5 |
| Max recall s.t. FPR ≤ 1e-3 | t = 0.5 (recall 0.99999) |
| Max F1 | t = 0.6 (F1 0.9999942; vs 0.5's 0.9999913 — a 3e-6 difference on 2 errors) |
| Deployed (frozen) | **t = 0.5** |

## 3. Interpretation — why t=0.5 is the right operating point

1. **In-distribution, the surface is flat from 0.3 to 0.7** (FPR 0.00169 → 0; recall constant at 0.99999). Any threshold in that band is statistically equivalent on dev data; the choice must be justified by *generalization*, not by in-distribution fine-tuning.
2. **Track B (never-seen families) caps the ceiling.** Held-out attack-family probabilities cluster near 0.62 median (measured in the tuning analysis): at t=0.7, unseen-family recall collapses (tuning Track B checks); at t ≤ 0.5 it stays ≥ 0.966. The dev-benign FPR benefit of t ≥ 0.6 is therefore bought with unseen-family recall — the wrong trade for a detector.
3. **t = 0.5 is the Pareto point**: it is the *highest-recall threshold that still meets the FPR ≤ 1e-3 target on held-out dev benign*, keeps the entire Track-B-safe probability region (0.3–0.5) inside its margin, and coincides with the sklearn default — no dataset-specific fine-tuning to explain.
4. **Operational cost:** at t = 0.5 on this split, 1 false alarm per 1,182 benign flows and 2 missed attacks per 172,496. Lower thresholds (0.05–0.2) multiply FP counts 6–21× (21 and 6 false alarms respectively) for zero recall gain; higher thresholds save at most 1 FP while risking unseen-family misses. On the broader benign estimate (all dev benign, 19,276 flows), the same t = 0.5 gives FPR 0.00042.

**Conclusion:** the deployed t=0.5 is simultaneously the FPR-target boundary, the F1-plateau center, and the unseen-family-safe ceiling. The sensitivity analysis finds no reason to prefer any other point — and the frozen artifact stays exactly as deployed.

*Figure: `reports/figures/research/threshold_sensitivity.png` (t=0.5 marked; log-scale FPR).*
