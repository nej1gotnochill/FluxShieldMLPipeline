"""ANALYSIS 1 — Exact-duplicate sensitivity (DEVELOPMENT DATA ONLY).

Question: do the strong development/evaluation results depend materially on
the 31,243 exact duplicate feature rows (~2.5%)?

Two complementary measurements, both on development captures only:
  S1. FROZEN-MODEL direct evaluation: the untouched calibrated artifact scores
      (a) the full dev table and (b) the deduplicated dev table at the frozen
      t=0.5. Methodologically valid for a sensitivity question: the model is
      already frozen, no selection happens, and the official final-test result
      is NOT recomputed or modified.
  S2. FROZEN-CONFIG retrain (separate experimental model): the exact ex-019
      ExtraTrees configuration retrained inside capture-disjoint A-2 folds on
      (a) full dev and (b) deduplicated dev. This answers whether *training*
      on duplicated rows materially inflates cross-validated performance.
      It is a sensitivity experiment ONLY — it never replaces the frozen model.

Capture-disjointness is preserved in S2 (duplicates are removed WITHIN the
folds; folds are rebuilt identically via make_group_folds with the same seed).
Deduplication is per-development-table with keep="first" — deterministic.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from feature_engineering import FEATURE_NAMES  # noqa: E402
from research_utils import (  # noqa: E402
    RESEARCH_DIR, a2_folds, dev_data, drop_duplicates_dev, evaluate_at_threshold,
    frozen_model, frozen_threshold, json_dump,
)
from tune import build_model  # noqa: E402
from utils import log, set_seeds, timed_stage  # noqa: E402


def tune_params() -> dict:
    """The frozen winner's exact params (ex-019), read from tuning_results.csv."""
    from config import load_config
    csv = Path(load_config().experiments_dir) / "tuning_results.csv"
    df = pd.read_csv(csv)
    row = df[df["trial_id"].str.contains("ex-019")].iloc[0]
    return eval(row["params"])


def main() -> None:
    cfg_seed = 42
    set_seeds(cfg_seed)
    t0 = time.perf_counter()

    with timed_stage(1, 3, "Loading dev data + frozen artifacts"):
        X, y, meta, _ = dev_data()
        model = frozen_model()
        t_op = frozen_threshold()
        log.info("dev table: %s flows x %d features | t_op=%.2f",
                 f"{len(y):,}", X.shape[1], t_op)

    results: list[dict] = []

    # ---------------- S1: frozen model, full vs dedup dev -------------------
    with timed_stage(2, 3, "S1: frozen-model direct evaluation (full vs dedup)"):
        p_full = model.predict_proba(X)[:, 1]
        m_full = evaluate_at_threshold(y, p_full, t_op)
        m_full["pr_auc_raw"] = float(__import__("sklearn.metrics", fromlist=["average_precision_score"])
                                     .average_precision_score(y, p_full))
        m_full["roc_auc_raw"] = float(__import__("sklearn.metrics", fromlist=["roc_auc_score"])
                                      .roc_auc_score(y, p_full))
        results.append({"experiment": "S1_frozen_full_dev", "n_rows": len(y),
                        "n_dup_removed": 0, **m_full})

        X_d, y_d, meta_d, n_dup = drop_duplicates_dev(X, y, meta)
        p_ded = model.predict_proba(X_d)[:, 1]
        m_ded = evaluate_at_threshold(y_d, p_ded, t_op)
        from sklearn.metrics import average_precision_score, roc_auc_score
        m_ded["pr_auc_raw"] = float(average_precision_score(y_d, p_ded))
        m_ded["roc_auc_raw"] = float(roc_auc_score(y_d, p_ded))
        results.append({"experiment": "S1_frozen_dedup_dev", "n_rows": len(y_d),
                        "n_dup_removed": n_dup, **m_ded})
        log.info("S1 full:  R=%.4f P=%.4f F1=%.4f FPR=%.5f | dedup: R=%.4f P=%.4f "
                 "F1=%.4f FPR=%.5f (dups removed=%d)",
                 m_full["recall"], m_full["precision"], m_full["f1"], m_full["fpr"],
                 m_ded["recall"], m_ded["precision"], m_ded["f1"], m_ded["fpr"], n_dup)

        # where do the duplicates live? (family composition of dup rows)
        dup_mask = X.duplicated(subset=list(FEATURE_NAMES), keep="first").to_numpy()
        dup_fam = meta.loc[dup_mask, "family"].value_counts()
        fam_table = dup_fam.rename_axis("family").reset_index(name="n_dups")
        fam_table["pct_of_family"] = (fam_table["n_dups"] /
                                      meta["family"].value_counts().reindex(fam_table["family"]).values * 100).round(3)
        fam_table.to_csv(RESEARCH_DIR / "dup_rows_by_family.csv", index=False)

    # ---------------- S2: frozen-config retrain, full vs dedup --------------
    with timed_stage(3, 3, "S2: frozen-config retrain on A-2 folds (full vs dedup)"):
        params = tune_params()
        log.info("frozen config params: %s", params)
        caps = meta["capture_file"].tolist()  # dev captures only
        groups = meta["capture_file"].to_numpy()

        # ONE capture partition shared by both arms: folds built on the full
        # dev table, then applied to the deduplicated table by capture name.
        # (Rebuilding folds per arm converges on different reshuffle seeds and
        # the benign distribution-shift fold lands at different positions —
        # an artifact, not a dedup effect. Matched partitions fix that.)
        folds, used_seed = a2_folds(caps, groups, y)
        fold_caps: dict[int, tuple[set, set]] = {}
        for fi, (tr, va) in enumerate(folds, start=1):
            fold_caps[fi] = (set(np.unique(groups[tr])), set(np.unique(groups[va])))
        log.info("shared capture partition built (seed offset %d)", used_seed)

        for label, Xe, ye, metae in (("full", X, y, meta), ("dedup", X_d, y_d, meta_d)):
            cap_arr = metae["capture_file"].to_numpy()
            rows = []
            for fi, (tr_caps, va_caps) in fold_caps.items():
                tr_m = np.isin(cap_arr, list(tr_caps))
                va_m = np.isin(cap_arr, list(va_caps))
                mdl = build_model("extra_trees", params, cfg_seed)
                mdl.fit(Xe.iloc[np.where(tr_m)[0]], ye[tr_m])
                pe = mdl.predict_proba(Xe.iloc[np.where(va_m)[0]])[:, 1]
                m = evaluate_at_threshold(ye[va_m], pe, t_op)
                m["fold"] = fi
                m["n_train_captures"] = len(tr_caps)
                rows.append(m)
                log.info("  S2[%s] fold %d: R=%.4f FPR=%.5f (benign=%d)", label, fi,
                         m["recall"], m["fpr"], m["n_benign"])
            agg = pd.DataFrame(rows)[["recall", "precision", "f1", "fpr", "fnr",
                                      "pr_auc", "roc_auc"]].agg(["mean", "std"])
            results.append({
                "experiment": f"S2_retrain_{label}", "n_rows": len(ye),
                "n_dup_removed": 0 if label == "full" else n_dup,
                "folds_used_seed": used_seed,
                "matched_capture_partition": True,
                "recall_mean": agg.loc["mean", "recall"], "recall_std": agg.loc["std", "recall"],
                "precision_mean": agg.loc["mean", "precision"],
                "f1_mean": agg.loc["mean", "f1"],
                "fpr_mean": agg.loc["mean", "fpr"],
                "fnr_mean": agg.loc["mean", "fnr"],
                "pr_auc_mean": agg.loc["mean", "pr_auc"],
                "roc_auc_mean": agg.loc["mean", "roc_auc"],
                **{f"fold{r['fold']}_{k}": v for r in rows for k, v in r.items()
                   if k in ("recall", "fpr")},
            })
            pd.DataFrame(rows).to_csv(RESEARCH_DIR / f"dup_sensitivity_S2_{label}_folds.csv",
                                      index=False)

    out = pd.DataFrame(results)
    out.to_csv(RESEARCH_DIR / "dup_sensitivity_results.csv", index=False)

    # machine-readable summary
    s1f, s1d = out.iloc[0], out.iloc[1]
    s2f, s2d = out.iloc[2], out.iloc[3]
    summary = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "seed": cfg_seed,
        "scope": "development captures only (final test untouched)",
        "original_dev_rows": int(s1f["n_rows"]),
        "duplicate_rows_removed": int(s1d["n_dup_removed"]),
        "deduplicated_dev_rows": int(s1d["n_rows"]),
        "duplicate_pct": round(100.0 * int(s1d["n_dup_removed"]) / int(s1f["n_rows"]), 3),
        "S1_frozen_model": {
            "full": {k: float(s1f[k]) for k in
                     ("recall", "precision", "f1", "fpr", "fnr", "pr_auc_raw", "roc_auc_raw")},
            "dedup": {k: float(s1d[k]) for k in
                      ("recall", "precision", "f1", "fpr", "fnr", "pr_auc_raw", "roc_auc_raw")},
            "abs_diff": {k: round(float(s1d[k]) - float(s1f[k]), 6) for k in
                         ("recall", "precision", "f1", "fpr", "fnr")},
        },
        "S2_frozen_config_retrain_A2": {
            "full": {k: float(s2f[f"{k}_mean"]) for k in
                     ("recall", "precision", "f1", "fpr", "fnr", "pr_auc", "roc_auc")},
            "dedup": {k: float(s2d[f"{k}_mean"]) for k in
                      ("recall", "precision", "f1", "fpr", "fnr", "pr_auc", "roc_auc")},
            "abs_diff": {k: round(float(s2d[f"{k}_mean"]) - float(s2f[f"{k}_mean"]), 6)
                         for k in ("recall", "precision", "f1", "fpr", "fnr")},
        },
        "note": "S1 evaluates the untouched frozen artifact; S2 is a separate "
                "experimental retrain that does NOT replace the deployed model.",
    }
    json_dump(summary, Path("reports/duplicate_sensitivity_results.json"))
    log.info("ANALYSIS 1 DONE in %.1fs", time.perf_counter() - t0)


if __name__ == "__main__":
    main()
