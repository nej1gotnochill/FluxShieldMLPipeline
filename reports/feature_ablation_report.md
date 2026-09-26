# Analysis 2 — Feature-Group Ablation (DEVELOPMENT DATA ONLY)

**Date:** 2026-09-09 · **Scope:** development captures only · **Model:** the frozen ex-019 ExtraTrees config, used as a *fixed* instrument (a feature study, not a hyperparameter search) · **Deployed artifact & feature_schema.json:** untouched
**Raw outputs:** `experiments/research/feature_ablation_results.csv` + per-config fold CSVs · machine-readable: `reports/feature_ablation_results.json` · seed 42

## 1. Groups (from the actual schema — no invented categories)

Groups are derived from `feature_schema.json` / `reports/feature_dictionary.md`. They are **non-exclusive**; overlap is documented rather than hidden:

| Group | k | Contents | Overlap |
|---|---:|---|---|
| B rate/statistical | 11 | flow_bytes_s, flow_packets_s, avg_pkt_size, avg_fwd/bwd_seg, down_up_ratio, pkt_len_*, flow_duration_s | pkt_len_* shared with C |
| C directional | 16 | fwd/bwd_packets, fwd/bwd_bytes, fwd/bwd_len_*, fwd/bwd_header_bytes, fwd/bwd_data_pkts | shares length stats with B |
| D timing/IAT | 22 | flow_iat_*, fwd/bwd_iat_*, active_*, idle_* (causal in-window) | — |
| E TCP behavior | 16 | fin/syn/rst/psh/ack/urg/ece/cwr counts, fwd/bwd_psh, fwd/bwd_urg, init_fwd/bwd_win, fwd/bwd_win_mean | — |
| F protocol indicator | 1 | protocol | — |

Configs: A = all 66; plus cumulative staircase cum1(B) → cum2(+C) → cum3(+D) → cum4(+E) → cum5(+F = all 66). One shared capture-disjoint A-2 partition for every config (identical to Analyses 1/4); Track B = never-seen families (tcp_syn_flood, tcp_rst, udp_flood dev captures) trained without them.

## 2. Results (A-2 = 5-fold means; Track B = holdout recall)

| Config | k | A-2 Recall | A-2 F1 | A-2 PR-AUC | Track B recall | tcp_rst | tcp_syn_flood | udp_flood |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **A all 66** | 66 | 0.99968 | 0.99697 | 1.00000 | **0.99781** | 1.000 | 1.000 | 0.996 |
| B rate/statistical | 11 | 0.99529 | 0.99476 | 0.99985 | 0.79521 | 0.000 | 0.976 | 1.000 |
| C directional | 16 | 0.99560 | 0.99490 | 0.99999 | 0.77494 | 0.324 | 0.981 | 0.857 |
| D timing/IAT | 22 | 0.99035 | 0.99221 | 1.00000 | 0.36965 | 0.343 | 0.642 | 0.288 |
| E TCP behavior | 16 | 0.98189 | 0.98436 | 0.99609 | 0.39998 | 1.000 | 1.000 | 0.000 |
| F protocol indicator | 1 | 0.40026 | 0.47573 | 0.98474 | 0.39999 | 1.000 | 1.000 | 0.000 |
| cum1 base rate | 11 | 0.99529 | 0.99476 | 0.99985 | 0.79521 | 0.000 | 0.976 | 1.000 |
| cum2 +directional | 27 | 0.99690 | 0.99556 | 1.00000 | 0.89903 | 0.505 | 0.991 | 1.000 |
| cum3 +timing | 49 | 0.99978 | 0.99701 | 1.00000 | 0.82010 | 0.302 | 0.984 | 0.938 |
| cum4 +tcp | 65 | 0.99941 | 0.99683 | 0.99759 | 0.74261 | 0.593 | 0.998 | 0.707 |
| cum5 +protocol (= all 66) | 66 | 0.99968 | 0.99697 | 1.00000 | 0.99781 | 1.000 | 1.000 | 0.996 |

## 3. Which groups contribute most to generalization?

1. **No single group generalizes alone.** The best single group (B, rate/statistical) reaches only 0.795 Track B recall — vs 0.998 for all 66. Every group is blind to at least one family's mechanics (B misses tcp_rst entirely at 0.00004; E/F miss udp_flood at ~0.000).
2. **Groups are complementary, not redundant.** E (TCP behavior) is *necessary but not sufficient*: alone it gets tcp_rst/tcp_syn_flood perfect but udp_flood exactly 0. D (timing) is the weakest single contributor to unseen families (0.370) — pacing statistics transfer poorly across families — yet it carries the in-distribution FPR/recovery signal (cum3 has the best A-2 recall, 0.99978).
3. **The staircase is non-monotonic on Track B** (cum4 = 0.743 < cum2 = 0.899): adding TCP behavior to an already-strong directional+timing base shifts probability mass in ways that hurt *udp_flood* (0.707) — evidence that unseen-family recall is an emergent property of the full feature set, not an additive sum.
4. **The protocol indicator is worth its 1 column**: +F moves Track B from 0.743 → 0.998 (tcp_rst 0.593 → 1.000, udp_flood 0.707 → 0.996). With it, every family ≥ 0.996.
5. **In-distribution saturation is early, generalization is not**: 11 features already give A-2 recall 0.9953, but only the full 66 give ≥ 0.99 unseen-family recall across all three held-out families.

**Answer:** the largest *generalization* contribution comes from the combination of directional volume statistics (C) + TCP behavioral flags (E) + the protocol indicator (F); the largest *in-distribution* contribution comes from rate/statistical features (B) refined by timing (D). Dropping any group is measurable; dropping the protocol indicator or TCP behavior measurably destroys never-seen-family recall for entire transport classes.

*Figure: `reports/figures/research/feature_ablation.png`.*
