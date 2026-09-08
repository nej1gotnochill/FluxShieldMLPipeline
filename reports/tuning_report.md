# STEP 9 — Hyperparameter Tuning Report

**Date:** 2026-09-08 · **Search:** randomized, 57 completed trials (40 ExtraTrees, 17 RandomForest) over the Track A-2 capture-disjoint folds (identical fold construction to the baselines) · **Selection metric:** mean PR-AUC, tie-break mean FNR · **Final test untouched.**

Raw records: `experiments/tuning_results.csv` (incremental, crash-safe), `experiments/tuning_trackb_check.csv`, `experiments/tuning_trackb_balanced_check.csv`.

## Search space and protocol

ExtraTrees/RandomForest over: `n_estimators` {100,200,300,500}, `max_depth` {None,12,20,28}, `min_samples_leaf` {1,2,5,10}, `max_features` {sqrt,0.3,0.5,0.75}, `class_weight` {balanced, balanced_subsample, None}, `criterion` {gini, entropy, log_loss}. Each trial = fit on the 5 A-2 training windows, evaluate on the paired validation captures; per-trial metrics averaged over folds.

**Early stop (documented):** the RF arm was stopped after 17/40 trials. Justification, all measured: (1) all 17 RF trials sit at mean PR-AUC 1.0 ± 2e-6 — no search signal; (2) every top-RF config chose `n_estimators=500` — the remaining trials explore depth/leaf/criterion with no headroom; (3) RF trials average 566 s (max 1925 s) → the remaining 23 trials ≈ 3.6 h of compute for information already gathered. Rule 6 of the hard rules prohibits running expensive searches blindly.

## Track A-2 results (in-distribution selection surface)

| Rank | Config | mean PR-AUC | mean recall | mean FPR | mean FNR | worst-fold FPR | trial s |
|---|---|---:|---:|---:|---:|---:|---:|
| ex-026 | ET entropy, depth 20, leaf 5, mf 0.75, cw None | 1.000000 | 0.99996 | 0.00149 | 0.00004 | 0.0063 | 87 |
| ex-019 | **ET gini, depth 20, leaf 1, mf sqrt, cw balanced, 300 trees** | 1.000000 | **0.99999** | **0.00067** | **0.00001** | 0.0030 | 70 |
| ra-004 | RF entropy, depth 20, leaf 2, mf 0.3, cw balanced_subsample, 500 trees | 1.000000 | 0.99980 | 0.00118 | 0.00021 | — | 748 |
| baseline | ET 100 trees, balanced (STEP 7) | 1.000000 | 0.9999 | 0.0007 | 0.0001 | 0.0033 | ~2 |

The A-2 surface is flat at the top: 40/40 ET trials within 5e-6 PR-AUC of each other. Selection by PR-AUC alone cannot discriminate — generalization must break the tie.

## The decisive finding: Track B generalization vs class_weight

Track B (never-seen families: tcp_syn_flood + tcp_rst + all udp_flood) for the A-2-selected winners vs the baselines:

| Config | class_weight | Track B recall | tcp_rst | tcp_syn_flood | udp_flood |
|---|---|---:|---:|---:|---:|
| baseline ET-100 (STEP 7) | balanced | **0.9740** | 0.9918 | 1.0000 | 0.9594 |
| ex-019 (300 trees) | **balanced** | **0.9664** | 0.9938 | 1.0000 | 0.9461 |
| ex-026 (A-2 "winner") | None | 0.7185 | 1.0000 | 1.0000 | 0.5309 |
| ex-024 (500 trees) | None | 0.6567 | 0.7407 | 0.9976 | 0.5150 |
| ra-004 (A-2 RF winner) | balanced_subsample | 0.1887 | 0.1592 | 0.7775 | 0.0023 |
| tuned RF w/o balanced | None | 0.19 (avg) | — | — | — |

**Reading:** dropping `class_weight` maximizes in-distribution PR-AUC (the majority attack class needs no reweighting when 97.6% of flows are attacks) but *destroys* generalization to never-seen families — the unweighted trees under-weight the minority-relevant structure. The baseline intuition (`balanced`) was right, and the search would have silently discarded it had PR-AUC been the only criterion. This is exactly why Track B exists.

## Selected final config (for STEPS 10–14)

`ExtraTrees(n_estimators=300, max_depth=20, min_samples_leaf=1, max_features='sqrt', class_weight='balanced', criterion='gini')` = **ex-019**

Rationale: statistically tied for best on A-2 (mean FNR 0.00001, FPR 0.00067 — both best-or-tied), 0.9664 Track B recall (within noise of baseline's 0.9740), trains 5× faster than any 500-tree config, 300 trees stabilize probability estimates for calibration (STEP 10). The plain baseline (100 trees, balanced) remains a legitimate simpler fallback under rule 12 (prefer simpler if equal) — difference in every measured metric is within fold noise; ex-019 is preferred for its lower FNR variance and stronger probability averaging.

## Honest caveats

- RF's Track B number (0.189) comes from its A-2-selected config, not an RF config chosen on Track B — RF with `class_weight=balanced` was not among its 17 sampled trials, so RF's true generalization ceiling was not measured. ET is nonetheless the safer choice: it dominates RF in the baseline comparison (0.974 vs 0.563) where both were balanced.
- The duplicate-heavy flood families (31,243 exact duplicate feature rows) inflate absolute recall numbers everywhere; relative model comparisons remain valid.
- No final-test data touched at any point in this phase.
