# Analysis 3 — Error Analysis (evaluation reads only; model untouched)

**Date:** 2026-09-09 · **Source data:** existing final-test flow tables + causal 1s re-extraction (`early_detection.extract_window_rows`) scored with the frozen pipeline · **Official artifacts:** untouched · **Consistency:** re-derived final-test metrics match `experiments/final_test_results.csv` exactly (R=0.997849, 952 FN, 1 FP)
**Raw outputs:** `experiments/research/error_family_evidence.csv`, `error_1s_family_evidence.csv`, `error_examples.csv` (representative FNs), `false_positives_all.csv` · machine-readable: `reports/error_analysis_results.json` · seed 42

## 1. Where the errors are (final test, full flows)

| Family | n flows | FN | FN rate | | Family | n | FN | rate |
|---|---:|---:|---:|---|---|---:|---:|---:|
| flash_traffic | 224,836 | 680 | 0.302 % | | tcp_syn_fast | 32,010 | 6 | 0.019 % |
| http_flood | 116,501 | 259 | 0.222 % | | tcp_syn_low | 16,017 | 3 | 0.019 % |
| http_low_rate | 9,597 | 2 | 0.021 % | | http_slow_header | 10,660 | 1 | 0.009 % |
| http_slow_body | 11,074 | 1 | 0.009 % | | http_slow_read | 21,826 | 0 | 0.000 % |

**False positives: exactly 1** of 5,555 benign flows (0.018 %), in the IDP benign capture.

## 2. Error taxonomy (evidence → cause → implication → future mitigation)

### Mode 1 — "Single-packet flow instances" (dominant: 939 of 952 FN = 98.6 %)
- **Observed evidence:** FN medians for flash_traffic (n=680) and http_flood (n=259): `flow_duration_s` = **0.000**, `n_packets` = **1**, `flow_packets_s` = **0.0**, syn=1 — vs detected peers of the same families: 3.0 s / 3 packets / ~1 pkt/s and 9.0 s / 21 packets. These are one-packet *instances* the terminal extractor legitimately emitted (activity-cap/timeout splits, client-side resets) — a flow record carrying essentially zero information.
- **Likely cause:** insufficient observation material, not model failure. No detector can distinguish a lone SYN from benign background without more evidence.
- **Operational implication:** the 0.9978 recall ceiling on this dataset is partly a *flow-construction* artifact; per-flow metrics understate per-attack-session detection because the same attack session also produces fully-featured flows that ARE detected (session-level recall would be higher).
- **Possible future mitigation (NOT implemented):** session-level aggregation or a minimum-packets-before-decision rule; flag one-packet instances as "indeterminate" instead of forcing a verdict.

### Mode 2 — "Long low-rate flows look benign" (13 FN: slow families 4, tcp_syn_* 9)
- **Observed evidence:** FN medians: duration **~380–1,020 s**, ~101–103 packets, ~0.10 pkt/s, syn=0 — the model's detected slow-flow peers run 64 s at the same 0.10 pkt/s; detected tcp_syn flows run 0.0008 s at ~3,600 pkt/s. The misses are flows that ran 6–16× longer and slower than anything the model learned to call attack, with no handshake flags (idle timeouts split them into flagless segments).
- **Likely cause:** rate/pacing statistics inside the benign support of the training distribution + missing TCP-state evidence in the FN segment.
- **Operational implication:** residual misses concentrate at the extreme-time tail; absolute counts are negligible (≤ 9 per family).
- **Possible future mitigation (NOT implemented):** longer-context features (minutes-scale windows) or explicit long-duration scoring path.

### Mode 3 — "1 s window: attack hasn't revealed itself yet" (early detection, measured)
The 1s causal re-extraction (n=256,223) shows recall 0.473 on the deep-dive subset with **precision-safe** failures — FNs had, at freeze time:

| family | 1s recall | FN medians (pkts / span / pkts/s) | detected peers (pkts / span / pkts/s) |
|---|---:|---|---|
| flash_traffic | 0.500 | 1 / 0.0 s / 0.0 | 2 / 1.00 s / 2.0 |
| http_low_rate | 0.593 | 1 / 0.0 s / 0.0 | 2 / 1.00 s / 2.0 |
| http_slow_body | 0.153 | 1 / 0.0 s / 0.0 | 7 / 0.82 s / 8.6 |
| http_slow_header | 0.120 | 1 / 0.0 s / 0.0 | 7 / 0.81 s / 8.6 |

- **Observed evidence:** 1s-window FNs are again one-packet rows (0.0 s of flow life observed). Notably http_slow_read keeps **0.999** at 1 s (its many parallel short segments are visible immediately), while the *pacing* families (slow_header/body, low_rate) are invisible until their second/third packets arrive inside the window.
- **Likely cause:** insufficient observation time; the distinguishing signal (inter-packet pacing, request repetition) physically does not exist yet at t=1 s. This is an information-theoretic limit, not a model defect — by 3 s all families recover to ≥ 0.997.
- **Operational implication:** a 1 s SLA is only compatible with high-rate flood detection (floods ≥ 0.95 at 1 s except the one-packet instances); slow-rate attacks need ≥ 3 s of observation.
- **Possible future mitigation (NOT implemented):** stream-level (not flow-level) aggregation across the same 5-tuple over time, or provisional labels with deferred decisions.

### Mode 4 — "The single false positive"
- **Observed evidence:** one benign flow (IDP capture), duration **320.6 s**, 0.04 pkt/s, 12.4 B/s, 330-byte packets, mean proba 0.829 — a long-lived low-rate flow whose profile resembles the slow-attack training manifold (benign flows in this dataset average 1.37 s / 6,551 pkt/s).
- **Likely cause:** benign distribution shift (documented: the dataset's benign captures are heterogeneous; IDP benign differs from httperf benign).
- **Operational implication:** FPR pressure comes from the benign tail, not the benign bulk; 1 FP per 5,555 benign flows is operationally negligible.
- **Possible future mitigation (NOT implemented):** more diverse benign training captures.

## 3. Early-window differences (1s vs 3s/5s vs full flow)

| window | flash_traffic | http_flood | http_low_rate | slow_body | slow_header | slow_read | tcp_syn_fast | tcp_syn_low |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 s | 0.500 | 0.949 | 0.593 | 0.153 | 0.120 | 0.999 | 1.000 | 1.000 |
| 3 s | 0.997 | 0.998 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| 5 s | 0.997 | 0.998 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| full | 0.997 | 0.998 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

3 s ≈ 5 s ≈ full flow for every family; the entire early-detection penalty is the 1 s window meeting families whose evidence arrives on 2–8 s timescales, plus one-packet instances that never carry evidence at any window.

## 4. What could NOT be established

- No evidence links the single FP to any capture-metadata artifact (its features are ordinary; the failure is genuinely feature-space).
- The 1s FPR (0.00288) vs full-flow FPR (0.00018) gap was NOT decomposable into specific benign flows: the 16 1s-window FPs are short benign flows whose early-window features (few packets) overlap the attack one-packet population of Mode 1. Same root cause, opposite sign: **less observed time → less separable.**

*Figure: `reports/figures/research/error_analysis.png`.*
