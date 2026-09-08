"""STEP 9 — Randomized hyperparameter search on the top-2 baseline models.

Scope (agreed in baseline review):
  * Models: extra_trees, random_forest (only)
  * Selection data: Track A-2 capture-group-disjoint folds (SAME folds as the
    baselines, rebuilt deterministically from the same seed logic)
  * Track B holdout is reported as a secondary check for the BEST configs only
  * NO final-test access (May 4-6 captures are never loaded)
  * NO threshold optimization, NO calibration here (STEPS 10-11)
  * Search: RandomizedSearchCV-style manual loop (keeps capture groups intact —
    sklearn's GroupKFold + random search done explicitly for full control)

Selection metric: mean PR-AUC across the 5 A-2 folds, tie-broken by mean FNR
(recall-oriented per the project goal). All metrics recomputed per fold.

Crash safety: every completed trial is appended to
experiments/tuning_results.csv immediately, so a session restart never loses
completed work. A resume pass skips already-recorded trial_ids.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path

import numpy as np
import pandas as pd

from config import load_config
from data_loader import load_flows
from evaluate import evaluate_binary, per_family_metrics
from feature_engineering import FEATURE_NAMES
from preprocessing import make_pipeline, sample_weights
from split import build_manifest, verify_manifest
from train import make_group_folds
from utils import log, set_seeds, timed_stage

EXPERIMENTS_CSV = "tuning_results.csv"

# --- search spaces (small, targeted; no blind huge grids) -------------------
SPACES = {
    "extra_trees": {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [None, 12, 20, 28],
        "min_samples_leaf": [1, 2, 5, 10],
        "max_features": ["sqrt", 0.3, 0.5, 0.75],
        "class_weight": ["balanced", "balanced_subsample", None],
        "criterion": ["gini", "entropy", "log_loss"],
    },
    "random_forest": {
        "n_estimators": [100, 200, 300, 500],
        "max_depth": [None, 12, 20, 28],
        "min_samples_leaf": [1, 2, 5, 10],
        "max_features": ["sqrt", 0.3, 0.5, 0.75],
        "class_weight": ["balanced", "balanced_subsample", None],
        "criterion": ["gini", "entropy", "log_loss"],
    },
}


def sample_trial(rng: np.random.Generator, model: str) -> dict:
    space = SPACES[model]
    return {k: space[k][rng.integers(len(space[k]))] for k in space}


def build_model(model: str, params: dict, seed: int):
    """Same pipeline shape as preprocessing.make_pipeline but parameterized."""
    if model == "extra_trees":
        from sklearn.ensemble import ExtraTreesClassifier
        from sklearn.pipeline import Pipeline
        return Pipeline([("model", ExtraTreesClassifier(random_state=seed, n_jobs=-1, **params))])
    if model == "random_forest":
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.pipeline import Pipeline
        return Pipeline([("model", RandomForestClassifier(random_state=seed, n_jobs=-1, **params))])
    raise ValueError(model)


def param_sig(model: str, params: dict) -> str:
    return f"{model}|{'|'.join(f'{k}={params[k]}' for k in sorted(params))}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-trials-per-model", type=int, default=40)
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    cfg = load_config()
    seed = args.seed if args.seed is not None else cfg.random_seed
    set_seeds(seed)

    with timed_stage(1, 5, "Loading split manifest"):
        m = build_manifest(cfg)
        if not verify_manifest(m):
            sys.exit(1)
        dev_caps = m[m["track_a_role"] != "final_test"]["capture"].tolist()

    with timed_stage(2, 5, "Loading development flow tables"):
        flows_dir = cfg.processed_dir / "flows"
        X, y, meta = load_flows(dev_caps, flows_dir)
        groups = meta["capture_file"].to_numpy()
        log.info("%s flows x %d features, attack frac %.4f", f"{len(y):,}", X.shape[1], y.mean())

    with timed_stage(3, 5, "Rebuilding A-2 folds (same construction as baselines)"):
        folds, used_seed = make_group_folds(dev_caps, groups, y, n_splits=5, seed0=cfg.random_seed)
        log.info("folds rebuilt with seed offset %d — identical to baseline A-2", used_seed)
        # precompute fold matrices once (avoid re-slicing per trial)
        fold_data = []
        for tr, va in folds:
            fold_data.append((X.iloc[tr], y[tr], X.iloc[va], y[va]))

    # Track B data (secondary check for best configs)
    b_tr_caps = m[m["track_b_role"] == "train"]["capture"].tolist()
    b_ho_caps = m[m["track_b_role"] == "holdout"]["capture"].tolist()
    b_tr_idx = meta["capture_file"].isin(b_tr_caps).to_numpy()
    b_ho_idx = meta["capture_file"].isin(b_ho_caps).to_numpy()
    B_X_tr, B_y_tr = X[b_tr_idx], y[b_tr_idx]
    B_X_ho, B_y_ho = X[b_ho_idx], y[b_ho_idx]
    B_meta_ho = meta.loc[b_ho_idx]

    out_dir = Path(cfg.experiments_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / EXPERIMENTS_CSV

    done: set[str] = set()
    if csv_path.exists():
        prev = pd.read_csv(csv_path)
        done = set(prev["trial_id"])
        log.info("resume: %d trials already recorded, skipping them", len(done))

    rng = np.random.default_rng(seed)
    run_id = uuid.uuid4().hex[:8]
    n_trials = args.n_trials_per_model

    with timed_stage(4, 5, f"Randomized search ({n_trials} trials/model)"):
        for model in ("extra_trees", "random_forest"):
            log.info("=== searching %s ===", model)
            trials_done = 0
            while trials_done < n_trials:
                params = sample_trial(rng, model)
                sig = param_sig(model, params)
                trial_id = f"{run_id}-{model[:2]}-{trials_done:03d}"
                if sig in done:
                    continue
                done.add(sig)

                # ---- evaluate on each A-2 fold ----
                fold_metrics: list[dict] = []
                t0 = time.perf_counter()
                for fi, (X_tr, y_tr, X_va, y_va) in enumerate(fold_data, start=1):
                    pipe = build_model(model, params, seed)
                    pipe.fit(X_tr, y_tr)
                    proba = pipe.predict_proba(X_va)[:, 1]
                    pred = (proba >= 0.5).astype(np.int64)
                    fm = evaluate_binary(y_va, pred, proba)
                    fm["fold"] = fi
                    fold_metrics.append(fm)
                train_s = time.perf_counter() - t0

                mets = pd.DataFrame(fold_metrics)
                rec = {
                    "run_id": run_id,
                    "trial_id": trial_id,
                    "model": model,
                    "params": str(params),
                    "mean_pr_auc": float(mets["pr_auc"].mean()),
                    "mean_recall": float(mets["recall"].mean()),
                    "mean_precision": float(mets["precision"].mean()),
                    "mean_f1": float(mets["f1"].mean()),
                    "mean_fpr": float(mets["fpr"].mean()),
                    "mean_fnr": float(mets["fnr"].mean()),
                    "mean_roc_auc": float(mets["roc_auc"].mean()),
                    "std_recall": float(mets["recall"].std()),
                    "worst_fold_recall": float(mets["recall"].min()),
                    "worst_fold_fpr": float(mets["fpr"].max()),
                    "total_train_s": round(train_s, 1),
                    "seed": seed,
                }
                # incremental write (crash-safe)
                pd.DataFrame([rec]).to_csv(csv_path, mode="a",
                                           header=not csv_path.exists(), index=False)
                log.info("  %s PR-AUC=%.6f R=%.4f FPR=%.5f FNR=%.5f (%.0fs)",
                         trial_id, rec["mean_pr_auc"], rec["mean_recall"],
                         rec["mean_fpr"], rec["mean_fnr"], rec["total_train_s"])
                trials_done += 1

    with timed_stage(5, 5, "Selecting best configs + Track B secondary check"):
        df = pd.read_csv(csv_path)
        df = df[df["run_id"] == run_id]
        best = {}
        for model in ("extra_trees", "random_forest"):
            sub = df[df["model"] == model].sort_values(
                ["mean_pr_auc", "mean_fnr"], ascending=[False, True])
            top = sub.iloc[0]
            best[model] = (top["params"], top)
            log.info("BEST %s: PR-AUC=%.6f R=%.4f FPR=%.5f | %s",
                     model, top["mean_pr_auc"], top["mean_recall"],
                     top["mean_fpr"], top["params"])
            log.info("  top-5 by PR-AUC:")
            for _, row in sub.head(5).iterrows():
                log.info("    R=%.4f FPR=%.5f FNR=%.5f %s",
                         row["mean_recall"], row["mean_fpr"], row["mean_fnr"], row["params"])

        # Evaluate each best config on Track B (never used for selection)
        b_rows = []
        for model, (params_str, _) in best.items():
            params = eval(params_str)  # written by us above
            pipe = build_model(model, params, seed)
            if model == "hist_gradient_boost":
                pipe.fit(B_X_tr, B_y_tr, model__sample_weight=sample_weights(B_y_tr))
            else:
                pipe.fit(B_X_tr, B_y_tr)
            proba = pipe.predict_proba(B_X_ho)[:, 1]
            pred = (proba >= 0.5).astype(np.int64)
            fam = per_family_metrics(B_meta_ho, B_y_ho, pred, proba)
            for _, fr in fam.iterrows():
                b_rows.append({"model": model, "family": fr["family"],
                               "n_flows": fr["n_flows"], "recall": fr["recall"]})
            log.info("Track B check %s: recall by family: %s", model,
                     {r["family"]: round(r["recall"], 4) for r in b_rows if r["model"] == model})
        bdf = pd.DataFrame(b_rows)
        bdf.to_csv(out_dir / "tuning_trackb_check.csv", index=False)
        log.info("saved %s and %s", csv_path, out_dir / "tuning_trackb_check.csv")

    log.info("TUNING DONE — best configs recorded; report before any further step.")


if __name__ == "__main__":
    main()
