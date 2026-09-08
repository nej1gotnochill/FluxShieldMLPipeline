# Figure Index

All figures are generated from measured artifacts. **No figure is fabricated or
retouched.** `dev` = development-only result · `final` = untouched final-test
result (never used for any selection).

## reports/figures/research/ (frozen-model research analyses, dev)

| File | Purpose | Source artifact | Status | Key takeaway |
|---|---|---|---|---|
| `duplicate_sensitivity.png` | Original vs deduplicated metrics (S1 frozen model; S2 matched-partition retrain with FP counts) | `reports/duplicate_sensitivity_results.json`, `experiments/research/dup_sensitivity_S2_*_folds.csv` | dev | Removing 16,709 duplicate dev rows changes metrics ≤ 1e-6 (S1) and fold recall by ≤ 0.0015 (S2) — results do not depend on duplicates |
| `feature_ablation.png` | Feature group vs recall, in-distribution (A-2) and never-seen-family (Track B) | `reports/feature_ablation_results.json` | dev | Single groups nearly saturate in-distribution (best 0.9953) but never generalize alone (best ≈ 0.795); full 66-feature schema reaches ≈ 0.998 Track-B |
| `error_analysis.png` | FN counts by family (final test) + 1s vs 3s recall for slow-rate families | `reports/error_analysis_results.json`, `reports/early_detection_results.json`, `experiments/research/error_1s_family_evidence.csv` | final + dev | 98.6% of final-test FN are one-packet flows; slow-rate families are invisible at 1 s and fully recovered by 3 s |
| `threshold_sensitivity.png` | Threshold vs recall/FPR/F1 (log-scale FPR) with t = 0.5 marked | `reports/threshold_sensitivity_results.json` | dev | t = 0.5 is the highest-recall threshold meeting FPR ≤ 1e-3; flat F1 plateau ≈ 0.3–0.7; higher thresholds risk unseen-family recall |

## reports/figures/ppt/ (SIH presentation figures)

Not yet generated. Expected set (per project convention):

| File | Purpose | Source artifact | Status | Key takeaway |
|---|---|---|---|---|
| `ppt_01_solution_architecture.png` | Pipeline architecture diagram | — (diagram, not measured data) | — | PCAP → flows → 66 features → capture-disjoint evaluation → frozen artifact |
| `ppt_02_model_comparison.png` | Baseline comparison on Tracks A-2/B | `experiments/baseline_results.csv` | dev | ExtraTrees uniquely combines precision and unseen-family recall (HGB collapses to 0.076) |
| `ppt_03_early_detection.png` | Recall/F1 by causal window (1/3/5 s) | `reports/early_detection_results.json` | final | 3 s matches full-flow recall (0.9979); 1 s is precision-safe but pacing-blind |
| `ppt_04_track_b_generalization.png` | Family-holdout recall by family | `experiments/baseline_family_recall.csv`, `reports/tuning_report.md` | dev | 0.974 aggregate on never-seen families; `class_weight=balanced` load-bearing |
| `ppt_05_final_performance.png` | Final untouched-test metrics + confusion matrix | `experiments/final_test_results.csv` | final | P 0.999998 / R 0.997849 / FPR 0.00018 on 448,076 unseen flows |
| `ppt_06_dataset_scale.png` | Dataset audit scale chart | `reports/dataset_inventory.json`, `reports/dataset_audit.md` | — | 45 pcaps · 37.84 GB · 98.7M packets · 1.24M flows |

## reports/figures/technical/

Reserved for technical-report figures regenerated from `experiments/` records
(baseline per-fold tables, tuning search history, calibration reliability
curves). None required for the current release; the source CSVs remain the
authoritative record.

---

Regeneration commands (only from existing measured artifacts):
`python src/research_figures.py` (research set). PPT figures above do not have
a committed generator yet; when created, they must read only from
`experiments/*.csv` and `reports/*_results.json`.
