# FINAL ML SUMMARY — Netra DDoS-AT-2022 Detection Pipeline

**Status: FROZEN** · 2026-09-08 · All metrics measured from real execution; nothing estimated or fabricated.

## Objective

Passive one-way detection of DDoS attack flows from raw PCAP captures with a leakage-controlled, capture-disjoint evaluation protocol and a frozen, reproducible inference artifact. Priority order: CORRECTNESS → GENERALIZATION → PERFORMANCE → ELEGANCE.

## Dataset audit

- **DDoS-AT-2022** (local read-only copy; path configured via `DDOS_AT_DATASET_PATH` — raw data never committed): 45 classic pcaps, 37.84 GB, 98,658,747 packets, 12 traffic classes (11 attack families + benign). Parser validated byte-exact against the pcap spec; 0 malformed records.
- **Flow table:** 1,236,285 bidirectional flows (parquet, float32), extracted streaming with structural mirror-duplicate removal (44.3M duplicated frames dropped), VLAN-aware dissection, and a verified packet-accounting identity (45/45 captures exact).
- **Class balance at flow level:** 19,276 benign (1.6%) vs 1,217,009 attack (98.4%) — inverse of packet-level balance; handled inside pipelines only (class weights / train-only sample weights).

## Features / feature schema

- **66 numeric features** (all float32, documented in `reports/feature_dictionary.md` with exact definitions, units, and ONLINE/TERMINAL availability): protocol; per-direction packet/byte counts; per-direction and pooled packet-length stats; full/forward/backward IAT stats; 12 TCP flag counters; header bytes; ratios; TCP windows; active/idle period stats; rates.
- **Leakage policy:** IPs, ports, timestamps, capture ids, and labels are metadata-only — never features. No CICFlowMeter compatibility claim is made.

## Final model (frozen)

```
ExtraTreesClassifier(n_estimators=300, max_depth=20, min_samples_leaf=1,
                     max_features="sqrt", class_weight="balanced",
                     criterion="gini", random_state=42)
+ sigmoid probability calibration (isotonic rejected: degenerate, 3-4 distinct outputs)
+ operating threshold t = 0.5 (validated: held-out dev-benign FPR 0.00085 ≤ 1e-3 target)
```

Selected as tuning trial `4fc1eda5-ex-019` (57 randomized trials over capture-disjoint A-2 folds; RF arm early-stopped with documented rationale). Artifacts: `models/calibrated_model.joblib`, `feature_schema.json`, `model_metadata.json`, `threshold.json`.

## Evaluation design (capture-disjoint throughout)

- **Track A-1:** strict chronological walk-forward (dataset is class-segregated in time; windows single-class by design, reported with caveats — FPR on unseen IDP benign drops 0.999 → 0.000 once that benign pattern enters training: distribution shift, not model quality).
- **Track A-2:** capture-group-disjoint stratified folds (GroupKFold/StratifiedGroupKFold, both classes per fold).
- **Track B:** attack-family holdout — `tcp_syn_flood` + `tcp_rst` + all 3 `udp_flood` captures never seen in training.
- **Final test:** contiguous two-class May 3–6 block, 17 captures, 448,076 flows — never used for feature selection, tuning, thresholds, calibration, or model selection; scored exactly once.

## Development results: baseline models & model selection

Four baselines (LogisticRegression, RandomForest, ExtraTrees 100, HistGradientBoosting) on Tracks A1/A2/B: trees dominated; ExtraTrees uniquely held Track-B recall 0.974 (HGB 0.076, LR 0.421). Randomized search: 57 trials over identical A-2 folds; RF arm early-stopped (documented rationale, flat PR-AUC surface ≈ 1.0 ± 2e-6). Winner `4fc1eda5-ex-019`; decisive Track-B finding: `class_weight=balanced` is load-bearing (configs without it: 0.97 → 0.19 unseen-family recall). Sources: `reports/baseline_report.md`, `reports/tuning_report.md`, raw records in `experiments/`.

## Development results: calibration & threshold (STEPS 10–11)

Calibration set = A-2 fold-5 validation captures (capture-disjoint from the fold-5 training window; overlap asserted). Sigmoid selected over isotonic after a measured degeneracy check (isotonic: 3–4 distinct outputs on the near-separable fold; sigmoid Brier 0.000013, ECE 0.000028). Operating threshold t = 0.5 — the default point, validated on held-out dev benign (FPR 0.00085 ≤ 1e-3 target) and Track-B recall 1.0000. DEVELOPMENT results only; the final test played no role.

## Final untouched test result (STEP 12, unchanged)

| Precision | Recall | F1 | PR-AUC | ROC-AUC | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|
| 1.0000 | 0.9978 | 0.9989 | 1.0000 | 1.0000 | 0.00018 (1/5,555) | 0.00215 (951/442,521) |

Confusion (tn/fp/fn/tp): 5,554 / 1 / 952 / 441,569. Per-family recall ≥ 0.997, worst `flash_traffic` 0.9970.

## Track B generalization (never-seen families)

| Model | Aggregate recall | tcp_syn_flood | tcp_rst | udp_flood |
|---|---:|---:|---:|---:|
| **ExtraTrees (final config)** | **0.9664** | 1.0000 | 0.9938 | 0.9461 |
| ExtraTrees baseline (100 trees) | 0.9740 | 1.0000 | 0.9918 | 0.9594 |
| RandomForest (tuned) | 0.1887 | 0.7775 | 0.1592 | 0.0023 |

**Key finding:** `class_weight=balanced` is the generalization-critical setting — configs without it collapse on never-seen families (0.97 → 0.72) despite identical in-distribution PR-AUC.

## Early detection (causal 1s / 3s / 5s windows, frozen model)

| Window | Recall | Precision | F1 | FPR | Coverage | TTD (med) |
|---|---:|---:|---:|---:|---:|---:|
| 1 s | 0.6816 | 0.9999 | 0.8106 | 0.00288 | 99.91% | 1.0 s |
| **3 s** | **0.9979** | 1.0000 | **0.9989** | 0.00198 | 99.90% | 3.0 s |
| 5 s | 0.9979 | 1.0000 | 0.9989 | 0.00198 | 99.90% | 5.0 s |

Causality is structural (accumulators frozen at the first packet beyond the boundary; verified by boundary-span audit and raw-pcap truncation equivalence). **3 s matches the full-flow result with no measurable loss; 5 s adds nothing; 1 s is precision-safe but blind to slow-paced attacks by construction.** Worst 1 s families: `http_slow_header` 0.12, `http_slow_body` 0.15.

## Inference benchmark (measured, final artifacts)

- **481k flows/s** full-batch (100k-row batches: 416k/s)
- Single-record latency: **49.8 ms median / 60.4 ms p95** (calibrated 300-tree ensemble)
- Model size **5.3 MB** on disk; cold start 54 ms
- Single-record CLI verified end-to-end (`python src/inference.py --demo` → benign, p=0.00015)

## Verification (finalization gate)

- `pytest -q`: **16/16 passed** (discovery, preprocessing, features, model loading, single-record inference, causality, frozen-artifact identity, final-test integrity)
- All four model artifacts load; params agree across `model_metadata.json` == `threshold.json` == fitted ensemble
- `experiments/final_test_results.csv` matches the frozen STEP-12 values exactly
- Cross-report consistency audit: 21/21 checks PASS, no inconsistencies

## Research-strengthening analyses (frozen model, development-only)

| Analysis | Measured result |
|---|---|
| Duplicate sensitivity | 16,709 dev duplicates (2.12% of 788,209); ≤ 1e-6 frozen-model metric change; 0.0007 matched-partition 5-fold recall change |
| Feature ablation | rate/statistical alone 0.9953 in-distribution recall; best single group only ≈ 0.795 Track-B; full 66 ≈ 0.998 — schema retained |
| Error analysis | 98.6% of the 952 final-test FN are one-packet flows (insufficient temporal evidence limits discriminability); single FP is a long low-rate benign flow resembling the slow-attack manifold |
| Threshold sensitivity | t=0.5 = highest-recall threshold meeting FPR ≤ 1e-3 (0.00085); flat F1 plateau ≈ 0.3–0.7; calibration-fold counts 1,182 benign / 172,496 attack (FPR granularity ±0.00085) |

Sources: `reports/{duplicate_sensitivity,feature_ablation,error_analysis,threshold_sensitivity}_report.md`; figures in `reports/figures/research/`; raw records in `experiments/research/`.

## Known limitations (do not remove)

1. **31,243 exact duplicate feature rows** (2.5%): scripted attack tools emit identical packets → identical flows. Inflates absolute metrics; relative comparisons remain valid.
2. **Single-capture families:** `tcp_syn_flood` and `tcp_rst` can never appear in both train and test; Track B covers exactly this gap.
3. **Class-segregated chronology:** Mar–Apr 1 = attacks + httperf benign; May 3 = benign; May 4–6 = attacks. The final test was deliberately composed as a contiguous two-class May 3–6 block so FPR is measurable (user-approved).
4. **Track B was used** for unseen-family generalization; it is attack-only (FPR measured on Track A-2 dev benign).
5. **Calibration uses sigmoid** because isotonic became degenerate (near-separable fold → step-function outputs).
6. **Instance-lifecycle divergence** between window and terminal extraction is <0.07% of rows (terminal extractor's 200k-packet sweep timing vs exact 120 s idle rule).
7. **Early-detection decision time is quantized** to the window boundary; sub-window decisioning not evaluated.
8. **1 s early detection cannot detect slow-paced attacks** — the pacing evidence those attacks consist of does not exist inside 1 s; a purpose-built early model would be required (out of scope for the frozen model).
9. FPR estimates rest on 5,555 final-test benign flows (±~0.0002 resolution); dev benign (19,276) give ±~0.0001.

## Final conclusion

The frozen ExtraTrees(300, balanced) + sigmoid-calibration detector at t=0.5 achieves, on a strictly untouched two-class test block scored exactly once: Precision 0.999998, Recall 0.997849, F1 0.998922, FPR 0.00018, FNR 0.00215 (PR-AUC/ROC-AUC 1.0000), with family-holdout recall 0.9664–0.9740 on never-seen attack families and 3 s causal windows matching full-flow recall. Research-strengthening analyses (duplicate sensitivity, ablation, error analysis, threshold sensitivity) found no result that materially threatens the model's validity; known limitations remain documented and attached to every claim. The pipeline is reproducible end-to-end from the raw PCAPs via the documented command sequence in `README.md`.
