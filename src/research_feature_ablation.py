"""ANALYSIS 2 — Feature-group ablation (DEVELOPMENT DATA ONLY).

Question: which feature groups actually contribute to DDoS detection and to
never-seen-family generalization?

Design:
  * Fixed model = the FROZEN ex-019 ExtraTrees configuration (a feature study,
    NOT another hyperparameter search).
  * One shared capture-disjoint A-2 partition (identical to Analyses 1/4) for
    every configuration — differences are attributable to features only.
  * Group configs (from the ACTUAL schema; overlap documented, not hidden):
      A all 66 | B rate/statistical | C directional | D timing/IAT
      E TCP behavior | F protocol indicator
  * Cumulative staircase: B -> +C -> +D -> +E -> +F(remaining) == all 66.
  * Track B: per config, train on Track-B-train captures, evaluate recall on
    the never-seen-family holdout (tcp_syn_flood, tcp_rst, udp_flood dev caps).

Nothing here modifies the deployed artifact or feature_schema.json.
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
    FEATURE_GROUPS, RESEARCH_DIR, a2_folds, dev_data, evaluate_at_threshold,
    json_dump,
)
from tune import build_model  # noqa: E402
from utils import log, set_seeds, timed_stage  # noqa: E402

PARAMS = {"n_estimators": 300, "max_depth": 20, "min_samples_leaf": 1,
          "max_features": "sqrt", "class_weight": "balanced", "criterion": "gini"}


def fit_eval(Xe, ye, tr, va) -> dict:
    mdl = build_model("extra_trees", PARAMS, 42)
    mdl.fit(Xe.iloc[tr], ye[tr])
    pe = mdl.predict_proba(Xe.iloc[va])[:, 1]
    return evaluate_at_threshold(ye[va], pe, 0.5)


def main() -> None:
    set_seeds(42)
    t0 = time.perf_counter()

    with timed_stage(1, 4, "Loading dev data + building shared partition"):
        X, y, meta, m = dev_data()
        dev_caps = m[m["track_a_role"] != "final_test"]["capture"].tolist()
        groups = meta["capture_file"].to_numpy()
        folds, used_seed = a2_folds(dev_caps, groups, y)
        log.info("shared A-2 partition (seed offset %d)", used_seed)

        # Track B split on dev captures
        b_hold_mask = meta["family"].isin(
            ("tcp_syn_flood", "tcp_rst", "udp_flood")).to_numpy()
        b_tr_idx = np.where(~b_hold_mask)[0]
        b_ho_idx = np.where(b_hold_mask)[0]
        log.info("Track B: train=%s flows, holdout=%s flows (families: %s)",
                 f"{len(b_tr_idx):,}", f"{len(b_ho_idx):,}",
                 sorted(meta.iloc[b_ho_idx]["family"].unique()))

    # -------- configurations --------
    G = FEATURE_GROUPS
    group_configs = {
        "A_all_66": list(FEATURE_NAMES),
        **{k: v for k, v in G.items()},
    }
    cumulative = {
        "cum1_base_rate": G["B_rate_statistical"],
        "cum2_+directional": G["B_rate_statistical"] + G["C_directional"],
        "cum3_+timing": G["B_rate_statistical"] + G["C_directional"] + G["D_timing_iat"],
        "cum4_+tcp": (G["B_rate_statistical"] + G["C_directional"]
                      + G["D_timing_iat"] + G["E_tcp_behavior"]),
        "cum5_+protocol_all66": list(FEATURE_NAMES),
    }
    configs = {**group_configs, **cumulative}

    with timed_stage(2, 4, f"A-2 fold evaluation ({len(configs)} configs x 5 folds)"):
        rows = []
        for cname, feats in configs.items():
            feats = [f for f in feats if f in FEATURE_NAMES]  # schema-safe
            out_csv = RESEARCH_DIR / f"ablation_folds_{cname}.csv"
            if out_csv.exists():  # crash-safe resume: reuse completed configs
                fdf = pd.read_csv(out_csv)
                agg = {k: float(fdf[k].mean()) for k in
                       ("recall", "precision", "f1", "pr_auc", "fpr", "fnr", "roc_auc")}
                agg_sd = {f"{k}_std": float(fdf[k].std()) for k in ("recall", "fpr")}
                rows.append({"config": cname, "n_features": len(feats),
                             "track": "A2", **agg, **agg_sd})
                log.info("  %-24s k=%2d  R=%.5f F1=%.5f FPR=%.5f PR-AUC=%.6f (cached)",
                         cname, len(feats), agg["recall"], agg["f1"], agg["fpr"],
                         agg["pr_auc"])
                continue
            Xe = X[feats]
            fold_rows = []
            for fi, (tr, va) in enumerate(folds, start=1):
                r = fit_eval(Xe, y, tr, va)
                r["fold"] = fi
                fold_rows.append(r)
            fdf = pd.DataFrame(fold_rows)
            agg = {k: float(fdf[k].mean()) for k in
                   ("recall", "precision", "f1", "pr_auc", "fpr", "fnr", "roc_auc")}
            agg_sd = {f"{k}_std": float(fdf[k].std()) for k in ("recall", "fpr")}
            rows.append({"config": cname, "n_features": len(feats),
                         "track": "A2", **agg, **agg_sd})
            fdf.insert(0, "n_features", len(feats))
            fdf.insert(0, "config", cname)
            fdf.to_csv(RESEARCH_DIR / f"ablation_folds_{cname}.csv", index=False)
            log.info("  %-24s k=%2d  R=%.5f F1=%.5f FPR=%.5f PR-AUC=%.6f",
                     cname, len(feats), agg["recall"], agg["f1"], agg["fpr"],
                     agg["pr_auc"])

    with timed_stage(3, 4, "Track B never-seen-family evaluation per config"):
        b_rows = []
        for cname, feats in configs.items():
            feats = [f for f in feats if f in FEATURE_NAMES]
            Xe = X[feats]
            mdl = build_model("extra_trees", PARAMS, 42)
            mdl.fit(Xe.iloc[b_tr_idx], y[b_tr_idx])
            pe = mdl.predict_proba(Xe.iloc[b_ho_idx])[:, 1]
            pred = (pe >= 0.5).astype(np.int64)
            fam_out = {}
            for fam in np.unique(meta.iloc[b_ho_idx]["family"]):
                fm = (meta.iloc[b_ho_idx]["family"].to_numpy() == fam)
                fam_out[fam] = {"n": int(fm.sum()), "recall": float(pred[fm].mean()),
                                "mean_proba": float(pe[fm].mean())}
            agg_recall = float(pred.mean())
            b_rows.append({"config": cname, "n_features": len(feats),
                           "trackB_agg_recall": agg_recall, **{f"tb_{k}_recall": v["recall"]
                                                               for k, v in fam_out.items()}})
            log.info("  %-24s TrackB R=%.4f | %s", cname, agg_recall,
                     {k: round(v["recall"], 3) for k, v in fam_out.items()})

    with timed_stage(4, 4, "Aggregating + saving"):
        a = pd.DataFrame(rows)
        b = pd.DataFrame(b_rows)
        merged = a.merge(b[["config", "trackB_agg_recall"]], on="config", how="left")

        base = merged[merged["config"] == "A_all_66"].iloc[0]
        for col in ("recall", "f1", "pr_auc"):
            merged[f"{col}_rel_degradation"] = (
                (base[col] - merged[col]) / base[col]).where(merged["config"] != "A_all_66", 0.0)

        merged.to_csv(RESEARCH_DIR / "feature_ablation_results.csv", index=False)

        out = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "seed": 42,
            "model_config": PARAMS,
            "partition_seed_offset": int(used_seed),
            "scope": "development only; fixed model config (feature study, not a search); "
                     "deployed artifact and feature_schema.json untouched",
            "feature_groups": {k: v for k, v in G.items()},
            "group_overlaps": {
                "note": "groups are non-exclusive: pkt_len_* counted in B and shared with "
                        "C's directional length stats; active/idle are timing features "
                        "computed causally; protocol is a single indicator feature",
                "pkt_len_features_in_B_and_C": sorted(
                    set(G["B_rate_statistical"]) & set(G["C_directional"])),
            },
            "results_A2_folds_mean": merged.to_dict(orient="records"),
            "results_trackB": b.to_dict(orient="records"),
        }
        json_dump(out, Path("reports/feature_ablation_results.json"))
        log.info("ANALYSIS 2 DONE in %.1fs", time.perf_counter() - t0)


if __name__ == "__main__":
    main()
