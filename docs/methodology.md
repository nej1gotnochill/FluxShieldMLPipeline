# Methodology

End-to-end methodology of the Netra pipeline, from raw packets to the
frozen detector. Every claim references a measured artifact.

## 1. Dataset handling

- **Source:** DDoS-AT-2022 — 45 classic PCAPs, ≈ 37.84 GB, 98,658,747 packets,
  11 attack families + benign. Obtained independently; configured via
  `DDOS_AT_DATASET_PATH` (never committed, never modified).
- **Parser:** custom little-endian PCAP reader validated byte-exact against
  the PCAP spec on the first records of every capture (offsets, incl_len/
  orig_len sanity, 0 malformed records) — `src/validate_pcap_parser.py`,
  `reports/dataset_audit.md`.
- **Discovery:** recursive; no Kaggle credentials, no downloads.

## 2. Flow extraction (`src/feature_engineering.py`)

- Streaming, constant-memory per worker (≈ 500 MB peak); parallel across
  captures; output written incrementally as per-capture Parquet row groups.
- Bidirectional 5-tuple flows, VLAN-aware dissection, idle timeout 120 s,
  activity cap 1800 s, 100k-packet cap.
- **Structural mirror-duplicate removal:** mirrored copies of frames (same
  timestamps within ~1 µs) are dropped via a bounded 128-entry deque; the
  packet-accounting identity (parsed = Σ flow packets + dups + non-IP +
  malformed + fragmented) was verified **exactly for 45/45 captures**
  (`reports/flow_validation_report.md`).
- 44.3M duplicated frames removed; 1,236,285 flows emitted (float32).

## 3. Feature representation

66 float32 features — directional counts, length/IAT statistics, TCP flag
counters, header bytes, ratios, TCP windows, active/idle periods, rates.
Documented exactly (definitions, units, ONLINE/TERMINAL availability) in
`reports/feature_dictionary.md`. Leakage policy: IPs, ports, timestamps,
capture ids, labels are metadata-only, enforced by a hard assertion in
`src/data_validation.py`. No CICFlowMeter compatibility is claimed.

## 4. Data quality / leakage audit

`src/data_validation.py` checks (fail-loud): schema, dtypes, NaN/inf (0),
exact duplicates (31,243 dataset-wide — reported, analyzed later, not
silently dropped), constant features (5 flagged), label integrity, leakage
identifiers, per-capture non-emptiness, cross-capture identical vectors
(sampled). Result: PASS with documented warnings
(`reports/data_validation_report.md`).

## 5. Evaluation design

Capture-disjoint throughout (see `docs/evaluation_protocol.md`):
A1 chronological walk-forward · A2 StratifiedGroupKFold(k=5) · Track B family
holdout · untouched May 3–6 final test. Manifest machine-verified
(`reports/split_manifest.csv`).

## 6. Model comparison (baselines)

Four models exactly as specified — LogisticRegression (scaled, balanced),
RandomForest(100), ExtraTrees(100), HistGradientBoosting(200, train-only
sample weights) — evaluated on all three tracks with class weights inside the
pipelines. Finding: trees dominate; ExtraTrees uniquely combines Track A
precision (FPR ≤ 0.0007) with Track B generalization (0.974 vs HGB's 0.076).
`reports/baseline_report.md`, `experiments/baseline_results.csv`.

## 7. Hyperparameter search (STEP 9)

Randomized search (no GridSearchCV): 57 completed trials (40 ExtraTrees, 17
RandomForest) over identical A-2 folds, incremental crash-safe records. The
surface was flat at PR-AUC ≈ 1.0; the RandomForest arm was early-stopped with
a documented rationale (zero search signal; ~9.5 min/trial remaining).
**Decisive finding:** configs winning in-distribution with
`class_weight=None` collapsed on never-seen families (Track B 0.97 → 0.19);
`class_weight="balanced"` is load-bearing for generalization.
`reports/tuning_report.md`, `experiments/tuning_results.csv`.

## 8. Selected configuration

`ex-019`: ExtraTrees(n_estimators=300, max_depth=20, min_samples_leaf=1,
max_features="sqrt", class_weight="balanced", criterion="gini",
random_state=42) — best-or-tied on A-2 (FNR 0.00001) and statistically tied
with the baseline's best on Track B (0.9664 vs 0.9740).

## 9. Calibration (STEPS 10–11)

Fit on fold-5's training window; fold-5 validation captures = calibration set
(capture-disjoint by construction; overlap asserted). Isotonic vs sigmoid
compared on Brier/ECE **plus a degeneracy guard**: isotonic collapsed to 3–4
distinct outputs on the near-separable fold, so sigmoid was selected for
threshold resolution. Brier 0.000013, ECE 0.000028.

## 10. Threshold selection

Data-fitted thresholds pin to extremes on a separable fold (documented), so
the operating point is t = 0.5, **validated** on held-out dev benign:
FPR 0.00085 ≤ 1e-3 target; recall 1.0000 on the calibration fold; Track-B
recall 1.0000. Rationale recorded in `models/threshold.json`.

## 11. Final untouched test (STEP 12)

Single pass after freezing: P 0.999998 · R 0.997849 · F1 0.998922 · FPR
0.00018 · FNR 0.00215 (confusion TN 5,554 / FP 1 / FN 952 / TP 441,569);
per-family recall ≥ 0.997. `reports/final_test_report.md`.

## 12. Early detection

Causal 1 s / 3 s / 5 s windows using the SAME `Flow` accumulator code frozen
at the first packet beyond the boundary — causality is structural, proven by
boundary-span checks and a raw-PCAP truncation audit (byte-identical rows).
Recall: 1 s 0.6816 → 3 s 0.9979 → 5 s 0.9979 (full-flow 0.9978).
`reports/early_detection_report.md`, `tests/test_early_detection.py`.

## 13. Research strengthening (frozen-model analyses, dev-only)

- **Duplicate sensitivity:** ≤ 1e-6 metric change (frozen model), 0.0007
  recall change (matched-partition retrain) after removing 16,709 dev
  duplicates. `reports/duplicate_sensitivity_report.md`.
- **Feature ablation:** rate features alone reach 0.9953 in-distribution, but
  no single group exceeds ≈ 0.795 Track-B recall; the full 66 reaches ≈ 0.998.
  Schema retained. `reports/feature_ablation_report.md`.
- **Error analysis:** 98.6 % of the 952 final-test FN are one-packet flows,
  where insufficient temporal evidence limits discriminability; the single FP
  is a long low-rate benign flow. `reports/error_analysis_report.md`.
- **Threshold sensitivity:** t = 0.5 is the highest-recall point meeting the
  FPR ≤ 1e-3 constraint; flat F1 plateau ≈ 0.3–0.7; higher thresholds risk
  unseen-family recall. `reports/threshold_sensitivity_report.md`.

## 14. Inference benchmark (STEP 13)

Measured: ≈ 481,000 flows/s batch; single-record median 49.8 ms / p95 60.4 ms;
model 5.3 MB. Single-record CLI demonstrated on a real flow
(`python src/inference.py --demo`). `reports/inference_benchmark.md`.

## 15. Reproducibility discipline

Seed 42 everywhere; every trial's raw record preserved under `experiments/`;
frozen artifacts hash-verified unchanged across all post-freeze analyses;
16/16 tests passing (`pytest -q`).
