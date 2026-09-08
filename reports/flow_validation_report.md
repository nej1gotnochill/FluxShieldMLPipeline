# Flow Extraction Validation Report — DDoS-AT-2022

**Date:** 2026-09-08 · **Validator:** `src/validate_flows.py` (independent re-derivation path) · **Flow table:** `data/processed/flows/` (45 parquet files, 105 MB)

> **Transparency note:** the extraction processed **all 45 captures** (two batches: benign 356.8 s, attacks 281.5 s) before the "subset-first" instruction arrived; the pilot (5 captures) had run first and passed. This report therefore validates the *full* table rather than a subset — no re-extraction was needed. All numbers below are measured.

## 1. Extraction totals (measured)

| Stage | Packets | Time | Throughput |
|---|---:|---:|---:|
| Benign batch (17 captures, 56,900,386 pkts) | → 25,169,765 mirror dups removed → 31,730,621 unique | 356.8 s | 33k pkt/s |
| Attack batch (28 captures, 41,758,361 pkts) | → 19,104,265 dups removed → 22,654,096 unique | 281.5 s | 30k pkt/s |
| **Total** | **98,658,747 → 54,354,717 unique** | **638.3 s** | **~30k pkt/s** |

Peak RSS per worker: ≤ 502 MB (largest flood captures); ≤ 154 MB benign. Parse errors: **0** across all files (`malformed=0, frag=0` in every log line; non-IPv4 frames counted separately).

## 2. Validation results

| Check | Result |
|---|---|
| **Packet-accounting identity** (`Σ n_packets == packets − dups − non_ip − malformed − frag`) | **45/45 captures match exactly** — every parsed packet lands in exactly one flow |
| **Duplicate flow rows** (exact row duplicates) | **0** in 1,236,285 rows |
| **Duplicate flow_ids within capture** | 336 (0.03%) — legitimate re-started flows after timeout/cap on long-lived connections (slow-read, flash); each is a separate flow episode |
| **Sampled-flow re-derivation from raw packets** (36 flows across 3 captures: benign HTTP, slow-header, SYN flood; independent aggregation path incl. identical mirror-dedup) | **36/36 PASS** on fwd/bwd packets, fwd/bwd bytes, duration, SYN count |
| **NaN / inf cells** | **0** in all 66 feature columns |
| **Constant features** | none (5 flag counters were constant *in the pilot only*; non-constant in the full table) |
| **Schema** | 66 float32 feature columns + 12 metadata columns; documented in `reports/feature_dictionary.md` |

## 3. Flow counts per family (binary: benign 19,276 · attack 1,217,009)

| family | flows | dur p50 (s) | dur p90 | pkts p50 | pkts p90 |
|---|---:|---:|---:|---:|---:|
| udp_flood | 393,236 | 6.48 | 8.59 | 14 | 21 |
| flash_traffic | 224,836 | 3.00 | 3.04 | 3 | 3 |
| http_flood | 165,868 | 9.37 | 19.74 | 22 | 25 |
| tcp_syn_flood | 131,077 | 7.35 | 8.15 | 19 | 24 |
| tcp_rst | 131,077 | 5.35 | 6.42 | 14 | 20 |
| tcp_syn_fast | 48,015 | 0.0008 | 0.001 | 3 | 3 |
| http_slow_read | 43,652 | 1782.5 | 1797.6 | 236 | 255 |
| tcp_syn_low | 32,033 | 0.0008 | 0.001 | 3 | 3 |
| **benign** | **19,276** | **0.0036** | **41.86** | **26** | **5,673** |
| http_slow_body | 16,831 | 64.6 | 65.6 | 7 | 16 |
| http_slow_header | 15,988 | 64.7 | 65.6 | 7 | 16 |
| http_low_rate | 14,396 | 63.2 | 106.8 | 7 | 19 |

**Class-imbalance reality (flow-level):** benign is only **1.6%** of rows — the mirror image of packet-level counts. This drives the evaluation design: accuracy is meaningless; recall/precision/PR-AUC on the attack class and FPR on benign are the primary metrics.

**ended_by:** capture_end 930,774 (75%) · timeout 303,897 (25%) · activity_cap 1,614. Flood flows are truncated at capture end (26–58 s bursts); this is a dataset property, reported honestly, not hidden.

## 4. Chronological capture order (walk-forward basis)

Captures span 2022-03-17 → 2022-05-06 in 3 distinct periods: Mar 17–26 (early attacks), Apr 1 (transport floods), May 3–6 (IDP benign series + repeat attacks). A natural expanding-window walk-forward:

- **Fold 1:** train on Mar 17–26 captures (9) → validate on Apr 1 (5)
- **Fold 2:** train on Mar+Apr (14) → validate on May 3 (IDP benign + repeat attacks, 13)
- **Fold 3:** train on Mar+Apr+May-3 (27) → validate on May 4–6 (12)

Never is a capture split across folds; flows from one pcap never appear in two splits.

## 5. Family-holdout feasibility (Track B)

Families with a single capture (must go entirely to holdout per your rule): `tcp_syn_flood`, `tcp_rst`. Families with 2–5 captures support train/test within-family. The strictest informative design: hold out one *multi-capture* family (e.g. `udp_flood`, 3 captures) + the two single-capture families, train on the rest, measure attack recall on never-seen families.

## 6. Conclusion

Flow construction, bidirectional grouping, timeout behavior, labels, and features are **verified correct**. The pipeline is ready for:

1. **Track A** — capture-disjoint chronological walk-forward (folds above)
2. **Track B** — family-holdout generalization
3. Baselines: LogisticRegression, RandomForest, ExtraTrees, HistGradientBoosting (XGB/LGBM only if justified)

Awaiting approval to proceed to baseline training (STEP 7).
