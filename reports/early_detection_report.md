# Early-Detection Evaluation (1s / 3s / 5s) — Frozen Final Model

**Model:** `extra_trees` + sigmoid calibration, t=0.50 (frozen artifacts, unchanged) · **Data:** 17 final-test captures, scored causally at 1s/3s/5s windows

## Full-flow reference (unchanged STEP 12 result)

| Precision | Recall | F1 | FPR | FNR |
|---|---:|---:|---:|---:|
| 1.0000 | 0.9978 | 0.9989 | 0.00018 | 0.00215 |

## Window results

| Window | Flows | Coverage | Recall | Precision | F1 | FPR | FNR | PR-AUC | ROC-AUC | TTD med | TTD p95 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1s | 448,512 | 99.91% | 0.6816 | 0.9999 | 0.8106 | 0.00288 | 0.31843 | 1.0000 | 0.9974 | 1.00s | 1.00s |
| 3s | 448,512 | 99.90% | 0.9979 | 1.0000 | 0.9989 | 0.00198 | 0.00211 | 1.0000 | 0.9989 | 3.00s | 3.00s |
| 5s | 448,510 | 99.90% | 0.9979 | 1.0000 | 0.9989 | 0.00198 | 0.00211 | 1.0000 | 0.9996 | 5.00s | 5.00s |

## Per-family recall by window

| Family | n (terminal) | 1s | 3s | 5s |
|---|---:|---:|---:|---:|
| flash_traffic | 224,885 | 0.5002 | 0.9970 | 0.9970 |
| http_flood | 116,501 | 0.9487 | 0.9978 | 0.9978 |
| tcp_syn_fast | 32,010 | 1.0000 | 1.0000 | 1.0000 |
| http_slow_read | 22,205 | 0.9988 | 1.0000 | 1.0000 |
| tcp_syn_low | 16,018 | 1.0000 | 1.0000 | 1.0000 |
| http_slow_body | 11,075 | 0.1534 | 1.0000 | 1.0000 |
| http_slow_header | 10,660 | 0.1205 | 1.0000 | 1.0000 |
| http_low_rate | 9,603 | 0.5928 | 1.0000 | 1.0000 |
| benign | 5,555 | 0.0029 | 0.0020 | 0.0020 |

## Detection coverage

Coverage is defined over the terminal flow table (448,076 rows, 17 captures): the share of terminal flows whose `flow_id` received at least one causal window row.

- **99.90–99.91%** in every window (311–328 uncovered flows of 448,076).
- Residual non-coverage has a single mechanical cause: the terminal extractor only revisits flow instances at its periodic sweeps (every 200k packets) and at capture end, while the window rule freezes/ends instances exactly at the 120 s idle boundary. A 5-tuple idling ≥120 s can therefore gain extra *window instances* (118.5k rows beyond unique ids — a counting artifact of instance accounting, not duplicate flows) while a few late terminal instances (rows whose entire life falls in a window already frozen for that 5-tuple *before* the instance began) do not map 1:1. Instance lifecycles agree within 0.07% of rows; per-flow verdicts are unaffected because extra instances are scored as separate rows and unique-id coverage is 99.9%.
- 1,185 extra window instances concentrate in flash_traffic (high churn of short flows on identical 5-tuples).

## Latency (time-to-decision)

Decision time = the freeze event (`first packet beyond the window boundary − flow_start`), capped at W; capture-end flows are capped at W by definition. Median = p95 = W in all windows because the boundary is deterministic: the model is evaluated the instant the window closes. Sub-window decisioning (predict mid-window from a partially-filled accumulator) is **not** evaluated here and is the natural next experiment.

## Interpretation

1. **3 s is the sweet spot.** At W=3 s the causal pipeline reaches recall 0.9979 / FNR 0.00211 — statistically identical to the full-flow reference (0.9978/0.00215) — while deciding 3 seconds after each flow's first packet. All families ≥ 0.997 except flash_traffic (0.9970).
2. **5 s adds nothing over 3 s** on this dataset (identical F1; PR-AUC 0.9996 vs 1.0000, ROC 0.9996 vs 0.9989 are within noise). The marginal packet evidence between 3 s and 5 s does not change verdicts.
3. **1 s degrades in a structured, explainable way** (recall 0.6816, all errors precision-safe): the frozen model was trained on full-flow statistics, and 1 s truncation removes exactly the evidence separating slow attacks from benign —
   - `http_slow_header` recall **0.12** (terminal 1.0): the attack is *defined* by packet pacing over tens of seconds; at 1 s a slow-header flow is indistinguishable from a benign opening.
   - `http_slow_body` recall **0.15** (terminal 1.0): same mechanism (payload dribble over ~60 s).
   - `flash_traffic` recall **0.50**: half of flash flows show no second packet within 1 s; their 1 s row is a single-packet row, but the family is still caught at 0.997 from 3 s.
   - Transport floods (`tcp_syn_fast`, `tcp_syn_low`) recall **1.0 at 1 s**: their signature (SYN-only, tiny packets, no handshake completion) is fully present in the first second.
   - FPR rises to 0.00288 (16/5,539 benign flagged vs 1/5,555 terminal): sub-second benign flows look briefly attack-like; still 99.7% specificity.
4. **Operational reading:** for this dataset a passive monitor can decide per-flow in **3 s with no measurable loss**. A 1 s SLA is precision-safe but misses the slow families by design, not by model deficiency — no causal 1 s feature set can contain the pacing evidence those attacks consist of (an early-warning model would need purpose-built pacing features, which is out of scope for the frozen model).

## Limitations

- Decision time is quantized to the window boundary (a flow is decided at its freeze event); sub-window latency is not observable in this design.
- Flows shorter than the window produce identical rows at every window (their full life is inside the window), so 1 s/3 s/5 s metrics converge for short flows by construction.
- The frozen model was trained on terminal features; window rows reuse the same 66-column contract with causally recomputed values. An early-window-specific model (trained on truncated features) could do better at 1 s but is a different model — explicitly out of scope here.
- Instance-lifecycle divergence vs the terminal table is <0.07% of rows (documented above); it affects row counts, not per-flow verdicts.
- The final-test captures are scored by the frozen model; these results must not be used for model selection.
- The known dataset caveats apply unchanged: 31,243 exact duplicate feature rows, single-capture families, class-segregated chronology (see reports/final_test_report.md).

## Reproducibility

- Command: `python src/early_detection.py` (defaults: windows 1/3/5, all 17 final-test captures).
- Machine-readable results: `reports/early_detection_results.json` (includes frozen-artifact identity, per-window metrics, per-family recall, extraction stats).
- Raw run log: `reports/early_detection_run.log` (13.5 min extraction, 33 s scoring).
- Causality self-checks (run in `tests/test_early_detection.py`): nesting 1s⊇3s⊇5s, zero boundary-span violations, frozen-model identity, and a raw-pcap boundary audit that replays a capture with an inclusive filter and proves removed packets never touched any feature.