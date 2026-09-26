# Netra — Passive One-Way Network Threat-Detection ML Pipeline

Leakage-aware near-real-time DDoS flow detection on the
[DDoS-AT-2022](https://link.springer.com/article/10.1007/s43538-023-00159-9)
dataset: 45 raw PCAPs (≈ 37.84 GB, 98,658,747 packets, 11 attack families +
benign) stream-processed into 1,236,285 bidirectional flows with 66 float32
features, evaluated under strict capture-disjoint protocol with a permanently
untouched final test — final Precision **0.999998**, Recall **0.997849**, FPR
**0.00018** on 448,076 unseen flows, with causal 1 s/3 s/5 s early-detection
evaluation.

> The raw DDoS-AT-2022 PCAPs are **intentionally NOT stored in this
> repository** because of their size (≈ 37.84 GB). The pipeline discovers
> them recursively from a locally configured path
> (`DDOS_AT_DATASET_PATH`). Obtain the dataset independently — see
> [Dataset access & citation](#dataset-access--citation).

## Problem

Passive DDoS detection must (a) never train on data the evaluation will
resemble — capture/session leakage silently inflates scores; (b) handle the
dataset's extreme flow-level imbalance (benign flows are only 1.6 % of
1,236,285 — the *inverse* of the packet-level balance); (c) generalize to
attack mechanics never observed in training; and (d) decide quickly, before a
flow completes. Most published pipeline evaluations on this class of dataset
violate (a); this repository is built to make such leakage structurally
impossible and independently verifiable.

## ML solution

A supervised, per-flow binary detector (attack / benign) with:

- a validated streaming PCAP → flow extractor (structural mirror-duplicate
  removal, packet-accounting identity verified exactly on 45/45 captures);
- a documented 66-feature representation (no CICFlowMeter compatibility
  claim; IPs/ports/timestamps/capture-ids are metadata-only, enforced by
  assertion);
- model comparison under capture-disjoint folds; randomized hyperparameter
  search whose Track-B check proved `class_weight="balanced"` is load-bearing
  for never-seen-family generalization;
- sigmoid probability calibration with an isotonic-degeneracy guard;
- a frozen operating threshold validated on held-out development benign data;
- a single, untouched final evaluation; causal early-window evaluation;
  and four research-strengthening analyses on the frozen model.

## Pipeline architecture

```
DDoS-AT-2022 PCAPs (local, read-only)
        │  validate_pcap_parser.py      byte-exact parser validation
        ▼
inspect_dataset.py  →  feature_engineering.py
        │                     streaming pcap → per-capture Parquet flow tables
        │                     (mirror-dup removal; accounting identity 45/45)
        ▼
validate_flows.py · verify_extraction.py · data_validation.py
        │                     independent re-derivation + leakage audit
        ▼
split.py              capture-disjoint manifest (machine-verified)
        ▼
train.py / tune.py    Track A1 / A2 / Track B evaluation, 57-trial search
        ▼
calibrate.py          sigmoid calibration + threshold validation (dev only)
        ▼
models/               FROZEN artifacts (joblib + schema + metadata + threshold)
        ▼
final_test.py         single untouched-test pass (May 3–6 block)
        ▼
early_detection.py    causal 1 s / 3 s / 5 s evaluation
        ▼
research_*.py         duplicate sensitivity · feature ablation · error
                      analysis · threshold sensitivity (frozen-model, dev-only)
        ▼
inference.py          reproducible single-record / batch scoring
```

## Dataset

| Property | Value |
|---|---|
| Source | DDoS-AT-2022 (CIC, Atlantic Technological University) |
| Captures | 45 classic PCAPs (little-endian) |
| Raw size | ≈ 37.84 GB on disk · 36.26 GB on wire |
| Packets | 98,658,747 |
| Classes | 11 attack families + benign (12 traffic classes) |
| Captures by label | 17 benign · 28 attack |

Extracted flow table: 1,236,285 flows (19,276 benign / 1,217,009 attack),
float32 Parquet. Per-family audit table:
[`reports/dataset_audit.md`](reports/dataset_audit.md).

## Feature representation

66 float32 features — directional packet/byte counts, per-direction and pooled
packet-length statistics, full/forward/backward IAT statistics, 12 TCP flag
counters, header bytes, ratios, TCP window sizes, active/idle period
statistics, rates. Every feature's exact definition, unit, and ONLINE/TERMINAL
availability is documented in
[`reports/feature_dictionary.md`](reports/feature_dictionary.md). Feature
availability is respected by the early-window extractor (terminal-only
features recomputed causally, never leaked). The ablation study
([`reports/feature_ablation_report.md`](reports/feature_ablation_report.md))
shows no single group reproduces the full representation's generalization —
the schema is retained whole.

## Model selection

Baselines (exactly four, no additions): LogisticRegression, RandomForest,
ExtraTrees, HistGradientBoosting — all evaluated on Tracks A1/A2/B. Trees
dominated; ExtraTrees was the only model strong on both in-distribution
precision (FPR ≤ 0.0007) and never-seen-family recall (0.974 vs HGB's 0.076).
The randomized search (57 trials, no GridSearchCV; the RF arm early-stopped
with documented rationale) confirmed `ex-019` as the winner:

```
ExtraTreesClassifier(n_estimators=300, max_depth=20, min_samples_leaf=1,
                     max_features="sqrt", class_weight="balanced",
                     criterion="gini", random_state=42)
+ sigmoid calibration (isotonic rejected: degenerate, 3–4 distinct outputs)
+ operating threshold t = 0.5 (validated: dev-benign FPR 0.00085 ≤ 1e-3)
```

Details: [`reports/baseline_report.md`](reports/baseline_report.md),
[`reports/tuning_report.md`](reports/tuning_report.md),
[`reports/calibration_report.md`](reports/calibration_report.md).

## Evaluation methodology

All splits are **capture-disjoint** (unit = PCAP, never a flow):

- **A1 — strict chronological walk-forward** (temporal robustness; windows
  single-class by dataset construction, reported with caveats).
- **A2 — capture-disjoint StratifiedGroupKFold(k=5)** (primary development
  track; both classes in every fold).
- **Track B — attack-family holdout** (`tcp_syn_flood`, `tcp_rst`, and all
  development `udp_flood` captures held out entirely).
- **Final test — untouched contiguous May 3–6 two-class block**, scored
  exactly once after everything was frozen.

Random flow-level splitting is not used anywhere as the primary evaluation
because flows from one capture share capture/session conditions (scripted
tools even emit byte-identical packets), which leaks the test distribution
into training. Full rationale and per-track results:
[`docs/evaluation_protocol.md`](docs/evaluation_protocol.md).

## Final results (untouched test — 448,076 flows, 17 captures, scored once)

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
Source: [`reports/final_test_report.md`](reports/final_test_report.md),
`experiments/final_test_results.csv`.

## Early detection (causal windows)

Features recomputed from raw packets using only packets within
`flow_start ≤ t ≤ flow_start + W`; accumulators frozen at the first future
packet (causality is structural, verified by boundary checks and a raw-PCAP
truncation audit):

| Window | Recall | Precision | F1 | FPR |
|---|---:|---:|---:|---:|
| 1 s | 0.6816 | 0.9999 | 0.8106 | 0.00288 |
| 3 s | 0.9979 | 1.0000 | 0.9989 | 0.00198 |
| 5 s | 0.9979 | 1.0000 | 0.9989 | 0.00198 |

1 s failures concentrate in pacing-revealed attacks (http_slow_header recall
0.12) where inter-packet evidence has not accumulated; all families recover
by 3 s. Source:
[`reports/early_detection_report.md`](reports/early_detection_report.md).

## Generalization (Track B family holdout)

Held out entirely from training: `tcp_syn_flood`, `tcp_rst`, all development
`udp_flood` captures.

| Family | Holdout recall |
|---|---:|
| **Aggregate** | **0.9740** |
| TCP SYN Flood | 1.0000 |
| TCP RST | 0.9918 |
| UDP Flood | 0.9594 |

The family-holdout evaluation demonstrates behavioral generalization to
attack families excluded from training; it does not establish guaranteed
detection of arbitrary zero-day attacks.

## Research-strengthening analyses (frozen model, development-only)

| Analysis | Headline finding |
|---|---|
| [Duplicate sensitivity](reports/duplicate_sensitivity_report.md) | 16,709 duplicate dev rows (2.12 % of 788,209); removing them changes metrics ≤ 1e-6 (frozen model) / 0.0007 recall (matched-partition retrain) |
| [Feature ablation](reports/feature_ablation_report.md) | rate/statistical alone: 0.9953 in-distribution recall, but best single group only ≈ 0.795 Track-B; full 66: ≈ 0.998 → schema retained |
| [Error analysis](reports/error_analysis_report.md) | 98.6 % of the 952 final-test FN are one-packet flows (insufficient temporal evidence limits discriminability); single FP is a long low-rate benign flow |
| [Threshold sensitivity](reports/threshold_sensitivity_report.md) | t = 0.5 is the highest-recall threshold meeting FPR ≤ 1e-3; flat F1 plateau ≈ 0.3–0.7; higher thresholds risk unseen-family recall |

Summary: [`reports/research_strengthening_summary.md`](reports/research_strengthening_summary.md).

## Repository structure

```
NetraMLPipeline/
├── README.md · FINAL_ML_SUMMARY.md · LICENSE · requirements.txt · .gitignore
├── configs/config.yaml            # DATASET_PATH via env var or this file
├── src/
│   ├── pcap layer:       inspect_dataset.py · validate_pcap_parser.py
│   ├── flow extraction:  feature_engineering.py · validate_flows.py · verify_extraction.py
│   ├── data:             data_loader.py · data_validation.py · split.py
│   ├── modelling:        preprocessing.py · train.py · tune.py · calibrate.py · evaluate.py
│   ├── serving:          inference.py · benchmark.py · final_test.py · export_metadata.py
│   ├── early_detection.py
│   ├── research:         research_utils.py · research_dup_sensitivity.py ·
│   │                     research_feature_ablation.py · research_error_analysis.py ·
│   │                     research_threshold_sensitivity.py · research_figures.py
│   └── common:           config.py · utils.py
├── tests/                         # 16 tests (pytest)
├── models/                        # FROZEN artifacts (5.3 MB joblib + 3 JSON)
├── reports/                       # measured reports + feature dictionary + figures/
├── experiments/                   # preserved raw records (incl. research/)
└── docs/                          # methodology · evaluation_protocol · model_card
```

## Installation

```bash
git clone https://github.com/nej1gotnochill/NetraMLPipeline.git
cd NetraMLPipeline
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Python 3.12 · scikit-learn 1.5.0 · numpy 2.5.2 · pandas 2.2.2 · pyarrow ·
dpkt (versions as measured in `models/model_metadata.json`).

## Reproduction instructions

Configure the dataset path first (never hard-coded):

```bash
export DDOS_AT_DATASET_PATH="/absolute/path/to/ddos-at-2022"   # local PCAP root
# or edit configs/config.yaml -> dataset.dataset_path
```

Full workflow — every stage is skip-logic safe and preserves its raw records:

```bash
# 0. dataset audit (parser validation + inventory)
python src/inspect_dataset.py --audit
python src/validate_pcap_parser.py

# 1. flow extraction (streaming; ~10.6 min for all 45 captures on 8 cores)
python src/feature_engineering.py

# 2. flow validation (independent re-derivation + accounting identity)
python src/verify_extraction.py
python src/validate_flows.py
python src/data_validation.py

# 3. split manifest (machine-verified, capture-disjoint)
python src/split.py

# 4. baselines on Tracks A1/A2/B
python src/train.py

# 5. randomized hyperparameter search (resumable, crash-safe records)
python src/tune.py --n-trials-per-model 40

# 6. calibration + threshold validation (development data only)
python src/calibrate.py --trial-id 4fc1eda5-ex-019

# 7. final untouched test — single pass
python src/final_test.py

# 8. early detection (causal 1/3/5 s)
python src/early_detection.py

# 9. inference benchmark
python src/benchmark.py

# 10. research-strengthening analyses (frozen model, dev-only)
python src/research_dup_sensitivity.py
python src/research_feature_ablation.py
python src/research_error_analysis.py
python src/research_threshold_sensitivity.py
python src/research_figures.py
```

The shipped frozen artifacts (`models/`) already encode steps 6–7's outcome;
steps 4–5 regenerate the selection evidence, steps 0–3 regenerate the flow
table the model consumes. Stage outputs land in `experiments/` and
`reports/` exactly as committed.

## Inference example

Single unseen flow record, no retraining (loads the frozen calibrated
pipeline; a real flow from the final-test table):

```bash
python src/inference.py --demo
```

```json
{
  "prediction": "benign",
  "attack_probability": 0.000154,
  "threshold": 0.5,
  "latency_ms": 72.1
}
```

Batch scoring of a flow table (Parquet/CSV with the 66-feature schema):

```bash
python src/inference.py --input data/processed/flows/<file>.parquet --out predictions.csv
```

Measured performance (frozen calibrated model, 5.3 MB): ≈ 481,000 flows/s
full-batch throughput (415,575 flows/s @100k batch) · single-record median
49.8 ms / p95 60.4 ms. Source:
[`reports/inference_benchmark.md`](reports/inference_benchmark.md).

## Tests

```bash
pytest -q          # 16 passed
```

Covers: dataset discovery, PCAP parser records, flow-table schema/labels,
feature computation, split-manifest disjointness, preprocessing fit-on-train,
model artifact loading, single-record inference, and causal early-window
extraction (including the raw-PCAP truncation audit).

## Limitations

- Absolute metrics are aided by ~2.5 % exact duplicate feature rows (scripted
  tools emit identical packets); the sensitivity analysis shows the
  *conclusions* do not depend on them (≤ 1e-6 change).
- `tcp_syn_flood` and `tcp_rst` are single-capture families; they can only be
  evaluated as unseen families (Track B), never within Track A.
- The dataset is class-segregated in time; strictly chronological windows are
  single-class (A1 caveat). Benign captures are heterogeneous (IDP vs
  httperf) — A1 measured a 0.9997 → 0.0006 FPR swing across that shift.
- 98.6 % of final-test FN are one-packet flows with insufficient temporal
  evidence; 1 s windows under-detect pacing-revealed attacks.
- Laboratory testbed data only; field transfer is untested.

Full list with context: [`docs/model_card.md`](docs/model_card.md),
[`FINAL_ML_SUMMARY.md`](FINAL_ML_SUMMARY.md).

## Dataset access & citation

The DDoSAT-2022 dataset was produced by the Canadian Institute for
Cybersecurity, Atlantic Technological University, and is publicly available
for research. Users must obtain it independently and configure the local path
via `DDOS_AT_DATASET_PATH` (or `configs/config.yaml`) — the raw data is
never bundled, downloaded, or committed.

> Agarwal, N., Sajid, S., Shithil, S. M., & Gaurav, A. K. (2023).
> *DDoSAT-2022: An intrusion detection dataset for distributed denial of
> service attacks.* Journal of Cyber Security and Migration, 2(2).
> https://doi.org/10.1007/s43538-023-00159-9

## License

[MIT](LICENSE) — code and trained artifacts; the dataset itself remains under
its own terms.
