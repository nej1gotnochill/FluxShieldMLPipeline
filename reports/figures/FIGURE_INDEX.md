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
(no invented values; 200 dpi PNG, white background, flat solid-color fills only).
`ppt_01/05/06` use a shared engineering/DFD design system (13.33×7.5 in canvas,
user palette: navy #12355B, blue #1976D2, green #2EAD62, yellow #F2C94C,
red #E74C3C, purple #7650C8 + light tints — no gradients, no shadows, no 3D);
a programmatic geometry audit fails the build on any text overflow, overlap or
arrow crossing before a figure can be saved.

| File | Purpose | Source artifact | Dataset split / status | Key takeaway | SIH-PPT suitable |
|---|---|---|---|---|---|
| `ppt_01_solution_architecture.png` | DFD-style ML-system architecture: four bordered stage panels (INPUT → FEATURE EXTRACTION → ML INFERENCE → DECISION) with solid stage chips, PASSIVE NETWORK TRAFFIC → PCAP/PACKET STREAM → FLOW CONSTRUCTION → 66-DIMENSIONAL FEATURE VECTOR rail feeding the five measured feature-group boxes (Timing 22 · Directional 16 · TCP 16 · Rate 11 · Protocol 1) into ExtraTrees → sigmoid calibration → probability → t = 0.5 → LEGITIMATE/DDoS cards; four-item bottom information strip (PASSIVE / FLOW-BASED / NO PAYLOAD INSPECTION REQUIRED / 3 s OBSERVATION WINDOW) | `reports/feature_ablation_results.json` (group partition), `reports/threshold_sensitivity_results.json` (t = 0.5 FPR), `experiments/benchmark.csv` (throughput/latency), `reports/early_detection_results.json` (3 s recall); structure per `README.md` | n/a (diagram; every stage fact cites its own artifact) | judges can read the full ML pipeline in ~5 seconds: passive capture → validated flows → 66 behavioral features → calibrated ExtraTrees → frozen decision rule | ✅ |
| `ppt_02_model_comparison.png` | Grouped bars: Recall & F1 for the 4 baselines | `experiments/baseline_results.csv` (Track A-2 5-fold means) | **development** (A-2) — labeled as such on the figure | ExtraTrees 99.99% recall / 99.99% F1 in-distribution, selected for precision + generalization (LR collapses to 84.4% recall); annotation points to Track-B figure | ✅ |
| `ppt_03_early_detection.png` | Recall & F1 vs causal window (1/3/5 s) with full-flow reference line | `reports/early_detection_results.json` + `experiments/final_test_results.csv` (reference only) | **final-test captures**, causal windows (frozen model) | recall 68.16% → 99.79% (3 s) → 99.79% (5 s); 3 s reaches essentially full-flow performance, 5 s adds nothing | ✅ |
| `ppt_04_track_b_generalization.png` | Horizontal bars: holdout recall per family + aggregate | `experiments/baseline_family_recall.csv` (Track B, ExtraTrees); aggregate 0.9740 per `reports/tuning_report.md` | **development** family holdout — labeled; caption states "not zero-day guarantee" | tcp_syn_flood 100.00% / tcp_rst 99.18% / udp_flood 95.94% / aggregate 97.40% on families entirely excluded from training | ✅ |
| `ppt_05_final_performance.png` | Flat evaluation sheet in four numbered sections — 1 · FINAL TEST PERFORMANCE (hero F1/Recall cards + Precision/FPR/FNR cards with measured TP/FP/FN bases + PR-AUC/ROC-AUC line), 2 · INFERENCE BENCHMARK (four equal benchmark cards), 3 · EARLY DETECTION (99.79% @ 3 s card with coverage and 1 s comparison), 4 · CONFUSION MATRIX (color-coded 2×2 with per-cell captions) — footer states frozen-artifact SHA-256 verification | `experiments/final_test_results.csv` (all detection metrics + confusion counts), `experiments/benchmark.csv` (throughput/latency/size), `reports/early_detection_results.json` (3 s recall + coverage) | **final untouched test** + benchmark (sections labeled on the figure) | strong detection performance + near-real-time inference: F1 99.8922% / Recall 99.7849% / FPR 0.0180% with 1 FP on 5,555 benign; 481K flows/s, 49.8 ms median; 3 s recall 99.79% | ✅ |
| `ppt_06_dataset_scale.png` | Flat dataset infographic in five numbered sections — 1 · DATASET SCALE (four equal headline cards: 45 captures / 98,658,747 packets / ~37.84 GB / 1,236,285 flows), 2 · DATASET COMPOSITION (17 benign / 28 attack / 11 families), 3 · PROCESSING PIPELINE (PCAP → packets → flows → 66-feature vectors, solid arrows), 4 · FEATURE REPRESENTATION (66-feature banner + exact group chips incl. TOTAL row), 5 · ATTACK FAMILY DIVERSITY (measured packets-per-family horizontal bars, per-family capture counts, "NOT balanced" title) + imbalance footnotes | `reports/dataset_inventory.json` (per-file packets/captures, summed per family), `reports/feature_ablation_results.json` (group partition), audited flow counts from `reports/dataset_audit.md` | full dataset (audit) | large-scale packet captures → validated flows → multidimensional behavioral representation, with real (labelled) class imbalance: 19,276 benign (1.6%) vs 1,217,009 attack flows; benign packets dominate volume | ✅ |

## reports/figures/technical/

Reserved for technical-report figures regenerated from `experiments/` records
(baseline per-fold tables, tuning search history, calibration reliability
curves). None required for the current release; the source CSVs remain the
authoritative record.

---

Regeneration commands (only from existing measured artifacts):
`python src/research_figures.py` (research set) · `python src/research_ppt_figures.py`
(PPT set). The generator reads `experiments/*.csv` and
`reports/*_results.json` / `reports/dataset_inventory.json` / frozen-artifact
JSONs directly — no value in the figures is hand-typed. A geometry audit
(text-in-box, pairwise text-overlap, canvas-bounds and arrow-crossing detection)
passed for all six PPT figures at commit time; the three restyled figures were
additionally verified gradient-free and text/piercing-clean by an independent
post-render scan.
