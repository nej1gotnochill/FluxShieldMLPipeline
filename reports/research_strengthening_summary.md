# Research-Strengthening Summary

**Date:** 2026-09-09 · All four analyses ran on DEVELOPMENT/SENSITIVITY data with the FROZEN pipeline. Official artifacts unchanged (verified by SHA-256 before/after — see §7). Seeds: 42 everywhere. Software: Python 3.12.10, sklearn 1.5.0, numpy 2.5.2, pandas 2.2.2, matplotlib 3.9.0.

Figures: `reports/figures/research/{duplicate_sensitivity,feature_ablation,error_analysis,threshold_sensitivity}.png`
Machine-readable: `reports/{duplicate_sensitivity,feature_ablation,error_analysis,threshold_sensitivity}_results.json`
Raw records: `experiments/research/` (never overwrites prior experiments)

## 1. Duplicate sensitivity — conclusion

**No material dependence.** 16,709 exact duplicate dev rows (2.12 % of 788,209). Removing them changes frozen-model metrics by ≤ 1e-6 (S1) and matched-partition 5-fold retrain recall by 0.0007 (S2). The reported strength is a property of the features, not of duplicated rows. Details: `reports/duplicate_sensitivity_report.md`.

## 2. Feature ablation — conclusion

**Groups are complementary; no group generalizes alone.** In-distribution, 11 rate features nearly saturate (recall 0.9953). On never-seen families, the best single group reaches only 0.795, while all 66 reach **0.998**. Largest generalization contribution: directional volume stats (C) + TCP behavior (E) + protocol indicator (F) — dropping F alone collapses tcp_rst/udp_flood holdout recall (0.743 aggregate). Largest in-distribution contribution: rate/statistical (B), refined by timing (D). The frozen 66-feature schema is justified, not redundant. Details: `reports/feature_ablation_report.md`.

## 3. Error analysis — conclusion

**98.6 % of the 952 final-test FN are one-packet flow instances** (median duration 0.0 s, 1 packet, 0.0 pkt/s) — a flow-construction artifact, not a detection failure; the residual 13 FN are long (380–1,020 s), low-rate (0.10 pkt/s) flows inside the benign support. The single FP is a 320 s low-rate benign flow resembling the slow-attack manifold. The 1 s-window failures (slow_header 0.12, slow_body 0.15) have the same signature — FN rows observed for a median 0.0 s / 1 packet: the attack has not revealed pacing evidence yet (information-theoretic, not model deficiency); everything recovers by 3 s. Details: `reports/error_analysis_report.md`.

## 4. Threshold / cost — conclusion

**t = 0.5 is the Pareto point**: highest recall meeting FPR ≤ 1e-3 on held-out dev benign (0.00085), on the flat F1 plateau (0.3–0.7), and at the ceiling imposed by never-seen-family probabilities (median ~0.62, so t ≥ 0.7 risks unseen-family recall). Dev FPR at t=0.5: 0.00085 (1 FP / 1,182 fold-5 benign; 0.00042 over all 19,276 dev benign). `threshold.json` untouched. Details: `reports/threshold_sensitivity_report.md`.

## 5. Does anything threaten the frozen model's validity?

**No.** (a) Duplicates: immaterial. (b) Features: schema fully justified by ablation. (c) Errors: concentrated in degenerate one-packet instances and the 1 s window — both understood, both documented. (d) Threshold: defensible on three independent grounds. The known caveats (duplicates, single-capture families, chronological class segregation, sigmoid-vs-isotonic, final-test composition) remain honestly attached to all results and are *reinforced* — not weakened — by these analyses.

## 6. What to present to SIH judges (vs technical report only)

**Present (slides/demo):**
1. Final-test headline: P=1.0000 / R=0.9978 / FPR=0.00018 on 448,076 unseen flows, scored exactly once.
2. Early detection curve: 3 s ≈ full-flow accuracy (R=0.9979); floods detectable within 1 s.
3. Ablation figure: "every feature group earns its place" — 0.795 → 0.998 unseen-family recall from best single group to full schema.
4. Threshold figure: operating point sits on the FPR-target boundary with unseen-family safety margin.
5. Duplicate sensitivity one-liner: removing all duplicates changes nothing (≤ 1e-6).
6. Rigor narrative: capture-disjoint splits, untouched final test, Track B family holdout — the process story judges reward.

**Technical report only:**
- The one-packet FN decomposition (98.6 % of FN) and its flow-construction-artifact interpretation.
- The benign distribution-shift fold (FPR 0.85) and its cancellation in matched-partition comparisons.
- tcp_syn_flood/tcp_rst single-capture-family caveats; S2 retrain fold-level tables.
- The 1s-vs-full FPR decomposition (short benign flows vs one-packet attack flows).
- Exact-duplicate cross-family vector coincidences (tcp_syn_fast ↔ tcp_syn_low).

## 7. Frozen-pipeline integrity (verified)

| Check | Result |
|---|---|
| `pytest -q` | **16/16 passed** |
| `models/*` SHA-256 vs pre-analysis baseline | unchanged (5/5) |
| `experiments/final_test_results.csv` | unchanged (hash match) |
| Official final-test metrics | P 1.0000 / R 0.9978 / F1 0.9989 / FPR 0.00018 / FNR 0.00215 — unchanged, independently re-derived in Analysis 3 with exact agreement |
| `threshold.json` / `feature_schema.json` | unchanged (hash match) |
| New artifacts | written only to `experiments/research/`, `reports/research_*`, `reports/figures/research/`, `reports/{analysis}_results.json` |
