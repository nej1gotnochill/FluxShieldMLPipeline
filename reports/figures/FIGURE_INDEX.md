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

All six generated from measured repository artifacts by `src/research_ppt_figures.py`
(no invented values; 200 dpi PNG, white background).

| File | Purpose | Source artifact | Dataset split / status | Key takeaway | SIH-PPT suitable |
|---|---|---|---|---|---|
| `ppt_01_solution_architecture.png` | End-to-end pipeline diagram (traffic → PCAP/flow processing → 66 features → ExtraTrees → sigmoid calibration → threshold 0.5 → verdict); emphasizes passive flow-based detection, no dashboard/frontend | structure per `README.md` + stage facts from `reports/*.md` (parser validation, calibration rationale, threshold validation) | n/a (diagram; stage facts cite their own reports) | clear passive-detection story: capture → features → calibrated probability → frozen decision rule | ✅ |
| `ppt_02_model_comparison.png` | Grouped bars: Recall & F1 for the 4 baselines | `experiments/baseline_results.csv` (Track A-2 5-fold means) | **development** (A-2) — labeled as such on the figure | ExtraTrees 99.99% recall / 99.99% F1 in-distribution, selected for precision + generalization (LR collapses to 84.4% recall); annotation points to Track-B figure | ✅ |
| `ppt_03_early_detection.png` | Recall & F1 vs causal window (1/3/5 s) with full-flow reference line | `reports/early_detection_results.json` + `experiments/final_test_results.csv` (reference only) | **final-test captures**, causal windows (frozen model) | recall 68.16% → 99.79% (3 s) → 99.79% (5 s); 3 s reaches essentially full-flow performance, 5 s adds nothing | ✅ |
| `ppt_04_track_b_generalization.png` | Horizontal bars: holdout recall per family + aggregate | `experiments/baseline_family_recall.csv` (Track B, ExtraTrees); aggregate 0.9740 per `reports/tuning_report.md` | **development** family holdout — labeled; caption states "not zero-day guarantee" | tcp_syn_flood 100.00% / tcp_rst 99.18% / udp_flood 95.94% / aggregate 97.40% on families entirely excluded from training | ✅ |
| `ppt_05_final_performance.png` | KPI board: final untouched-test metrics + inference benchmark | `experiments/final_test_results.csv` + `experiments/benchmark.csv` | **final untouched test** + benchmark (labeled on the figure) | P 99.9998% / R 99.7849% / F1 99.8922% / FPR 0.0180%; 481K flows/s, 49.8 ms median, 60.4 ms P95, 5.3 MB; 3 s recall 99.79% | ✅ |
| `ppt_06_dataset_scale.png` | Infographic: dataset scale + captures by label + packets by class | `reports/dataset_audit.md` + `reports/dataset_inventory.json` (17/28 captures; packets-per-family table) | full dataset (audit) | 45 PCAPs · 98.7M packets · ~37.84 GB · 1,236,285 flows · 66 features · 11 attack families (17 benign / 28 attack captures) | ✅ |

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
