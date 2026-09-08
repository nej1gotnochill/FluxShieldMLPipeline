"""Baseline training on the validated DDoS-AT-2022 flow table.

[1/6] Load split manifest (verified)
[2/6] Load flow tables (parquet, float32)
[3/6] Track A-1: strict chronological walk-forward (single-class windows reported with caveats)
[4/6] Track A-2: capture-group-disjoint stratified folds (GroupKFold on pcaps,
     seeded reshuffle until every validation fold contains BOTH classes)
[5/6] Track B: attack-family holdout (tcp_syn_flood, tcp_rst, udp_flood held out)
[6/6] Aggregate, save experiment records

Hard rules honoured:
  * no tuning, no threshold optimization, no calibration
  * final test (May 4-6 captures) is NEVER loaded or touched
  * preprocessing fitted on training data only (inside sklearn Pipeline)
  * class imbalance handled via class_weight / train-only sample weights
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupKFold

from config import load_config
from data_loader import load_flows
from evaluate import evaluate_binary, measure_inference, per_family_metrics
from feature_engineering import FEATURE_NAMES
from preprocessing import MODELS, make_pipeline, sample_weights
from split import TRACK_A_FOLDS, build_manifest, verify_manifest
from utils import log, set_seeds, timed_stage


def run_one(model_name, X_tr, y_tr, X_va, y_va, meta_va, seed) -> tuple[dict, pd.DataFrame]:
    pipe = make_pipeline(model_name, seed=seed)
    t0 = time.perf_counter()
    if model_name == "hist_gradient_boost":
        pipe.fit(X_tr, y_tr, model__sample_weight=sample_weights(y_tr))
    else:
        pipe.fit(X_tr, y_tr)
    train_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    proba = pipe.predict_proba(X_va)[:, 1]
    pred = (proba >= 0.5).astype(np.int64)
    infer_s = time.perf_counter() - t0

    m = evaluate_binary(y_va, pred, proba)
    m.update({
        "model": model_name,
        "train_s": round(train_s, 2),
        "val_s": round(infer_s, 2),
        "val_throughput_flows_s": round(len(X_va) / max(infer_s, 1e-9)),
        "val_n_benign": int((y_va == 0).sum()),
        "val_n_attack": int((y_va == 1).sum()),
    })
    ft = per_family_metrics(meta_va, y_va, pred, proba)
    return m, ft


def log_result(r: dict) -> None:
    caveat = ""
    if r["val_n_benign"] == 0:
        caveat = "  [attack-only window: FPR/PR-AUC/ROC undefined]"
    elif r["val_n_attack"] == 0:
        caveat = "  [benign-only window: recall/F1/FNR undefined]"
    log.info("  %-22s P=%-6s R=%-6s F1=%-6s PR-AUC=%-6s ROC=%-6s FPR=%-7s FNR=%-7s (%.1fs train)%s",
             r["model"],
             f"{r['precision']:.4f}" if np.isfinite(r["precision"]) else "  nan ",
             f"{r['recall']:.4f}" if np.isfinite(r["recall"]) else "  nan ",
             f"{r['f1']:.4f}" if np.isfinite(r["f1"]) else "  nan ",
             f"{r['pr_auc']:.4f}" if np.isfinite(r["pr_auc"]) else "  nan ",
             f"{r['roc_auc']:.4f}" if np.isfinite(r["roc_auc"]) else "  nan ",
             f"{r['fpr']:.4f}" if np.isfinite(r["fpr"]) else "  nan ",
             f"{r['fnr']:.4f}" if np.isfinite(r["fnr"]) else "  nan ",
             r["train_s"], caveat)


def make_group_folds(caps: list[str], groups: np.ndarray, y: np.ndarray,
                     n_splits: int = 5, seed0: int = 42, max_tries: int = 60):
    """Capture-disjoint folds with both classes in every fold.

    StratifiedGroupKFold (group-safe + class-aware); seeded reshuffles until
    every fold contains both classes. Falls back to plain GroupKFold with
    permutation ranks (legacy behaviour) if SGKF cannot satisfy the constraint.
    """
    from sklearn.model_selection import StratifiedGroupKFold
    unique = sorted(set(caps))
    for s in range(max_tries):
        sgkf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True,
                                    random_state=seed0 + s)
        folds, ok = [], True
        for tr, va in sgkf.split(groups, y, groups=groups):
            if len(np.unique(y[va])) < 2:
                ok = False
                break
            folds.append((tr, va))
        if ok:
            return folds, s
    # legacy fallback: GroupKFold over permuted rank labels
    for s in range(max_tries):
        rng = np.random.default_rng(seed0 + 1000 + s)
        order = rng.permutation(unique)
        rank = {c: i for i, c in enumerate(order)}
        g = np.array([rank[c] for c in groups])
        gkf = GroupKFold(n_splits=n_splits)
        folds, ok = [], True
        for tr, va in gkf.split(g, groups=g):
            if len(np.unique(y[va])) < 2:
                ok = False
                break
            folds.append((tr, va))
        if ok:
            return folds, 1000 + s
    raise RuntimeError("could not build mixed-class group folds")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=list(MODELS), choices=MODELS)
    ap.add_argument("--skip-track-b", action="store_true")
    ap.add_argument("--a2-folds", type=int, default=5)
    args = ap.parse_args()

    cfg = load_config()
    set_seeds(cfg.random_seed)

    with timed_stage(1, 6, "Loading split manifest"):
        m = build_manifest(cfg)
        if not verify_manifest(m):
            sys.exit(1)
        dev_caps = m[m["track_a_role"] != "final_test"]["capture"].tolist()
        log.info("development captures: %d (final test %d untouched)",
                 len(dev_caps), int((m["track_a_role"] == "final_test").sum()))

    with timed_stage(2, 6, "Loading flow tables"):
        flows_dir = cfg.processed_dir / "flows"
        X, y, meta = load_flows(dev_caps, flows_dir)
        log.info("loaded %s flows x %d features, attack fraction %.4f",
                 f"{len(y):,}", X.shape[1], float(y.mean()))

    results: list[dict] = []
    fam_tables: list[pd.DataFrame] = []

    # ---------------- Track A-1: strict chronological walk-forward ----------
    with timed_stage(3, 6, "Track A-1: strict chronological walk-forward"):
        log.info("NOTE: dataset is class-segregated in time; windows are single-class by design.")
        for fold, (ts, te, vs, ve) in enumerate(TRACK_A_FOLDS, start=1):
            tr_caps = m.iloc[ts:te]["capture"].tolist()
            va_caps = m.iloc[vs:ve]["capture"].tolist()
            tr_idx = meta["capture_file"].isin(tr_caps).to_numpy()
            va_idx = meta["capture_file"].isin(va_caps).to_numpy()
            X_tr, y_tr = X[tr_idx], y[tr_idx]
            X_va, y_va = X[va_idx], y[va_idx]
            meta_va = meta.loc[va_idx]
            log.info("fold %d: train=%s flows (%d caps), val=%s flows (%d caps; benign=%d attack=%d)",
                     fold, f"{len(y_tr):,}", len(tr_caps), f"{len(y_va):,}", len(va_caps),
                     int((y_va == 0).sum()), int((y_va == 1).sum()))
            for name in args.models:
                r, ft = run_one(name, X_tr, y_tr, X_va, y_va, meta_va, cfg.random_seed)
                r.update({"track": "A1", "fold": fold})
                ft.insert(0, "fold", fold)
                ft.insert(0, "model", name)
                ft.insert(0, "track", "A1")
                results.append(r)
                fam_tables.append(ft)
                log_result(r)

    # ---------------- Track A-2: capture-group stratified folds -------------
    with timed_stage(4, 6, f"Track A-2: capture-group stratified folds (k={args.a2_folds})"):
        groups = meta["capture_file"].to_numpy()
        folds, used_seed = make_group_folds(dev_caps, groups, y, n_splits=args.a2_folds,
                                            seed0=cfg.random_seed)
        log.info("group folds built with seed offset %d; every fold has both classes", used_seed)
        for fi, (tr_idx, va_idx) in enumerate(folds, start=1):
            X_tr, y_tr = X.iloc[tr_idx], y[tr_idx]
            X_va, y_va = X.iloc[va_idx], y[va_idx]
            meta_va = meta.iloc[va_idx]
            log.info("fold %d: train=%s flows (%d caps), val=%s flows (%d caps; benign=%d attack=%d)",
                     fi, f"{len(y_tr):,}", len(np.unique(groups[tr_idx])),
                     f"{len(y_va):,}", len(np.unique(groups[va_idx])),
                     int((y_va == 0).sum()), int((y_va == 1).sum()))
            for name in args.models:
                r, ft = run_one(name, X_tr, y_tr, X_va, y_va, meta_va, cfg.random_seed)
                r.update({"track": "A2", "fold": fi})
                ft.insert(0, "fold", fi)
                ft.insert(0, "model", name)
                ft.insert(0, "track", "A2")
                results.append(r)
                fam_tables.append(ft)
                log_result(r)

    # ---------------- Track B: family holdout --------------------------------
    if not args.skip_track_b:
        with timed_stage(5, 6, "Track B: family holdout"):
            b_tr = m[m["track_b_role"] == "train"]["capture"].tolist()
            b_ho = m[m["track_b_role"] == "holdout"]["capture"].tolist()
            b_tr_idx = meta["capture_file"].isin(b_tr).to_numpy()
            b_ho_idx = meta["capture_file"].isin(b_ho).to_numpy()
            X_tr, y_tr = X[b_tr_idx], y[b_tr_idx]
            X_va, y_va = X[b_ho_idx], y[b_ho_idx]
            meta_va = meta.loc[b_ho_idx]
            log.info("track B: train=%s flows (%d caps), holdout=%s flows (%d caps; benign=%d attack=%d)",
                     f"{len(y_tr):,}", len(b_tr), f"{len(y_va):,}", len(b_ho),
                     int((y_va == 0).sum()), int((y_va == 1).sum()))
            log.info("  held-out families: %s", ", ".join(sorted(meta_va["family"].unique())))
            for name in args.models:
                r, ft = run_one(name, X_tr, y_tr, X_va, y_va, meta_va, cfg.random_seed)
                r.update({"track": "B", "fold": "holdout"})
                ft.insert(0, "fold", "holdout")
                ft.insert(0, "model", name)
                ft.insert(0, "track", "B")
                results.append(r)
                fam_tables.append(ft)
                log_result(r)

    # ---------------- aggregate + save ---------------------------------------
    with timed_stage(6, 6, "Aggregating + saving"):
        # inference timing: measured once per model on the largest validation set
        # (chronological fold 1 = 655k flows) for throughput, plus single-row latency.
        big_va = m.iloc[TRACK_A_FOLDS[0][2]:TRACK_A_FOLDS[0][3]]["capture"].tolist()
        big_tr = m.iloc[TRACK_A_FOLDS[0][0]:TRACK_A_FOLDS[0][1]]["capture"].tolist()
        tr_idx = meta["capture_file"].isin(big_tr).to_numpy()
        va_idx = meta["capture_file"].isin(big_va).to_numpy()
        X_va = X[va_idx]
        for name in args.models:
            pipe = make_pipeline(name, seed=cfg.random_seed)
            if name == "hist_gradient_boost":
                pipe.fit(X[tr_idx], y[tr_idx], model__sample_weight=sample_weights(y[tr_idx]))
            else:
                pipe.fit(X[tr_idx], y[tr_idx])
            t = measure_inference(pipe, X_va)
            for r in results:
                if r["model"] == name and r.get("track") == "A1" and r.get("fold") == 1:
                    r.update(t)

        out_dir = Path(cfg.experiments_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        df = pd.DataFrame(results)
        csv_path = out_dir / "baseline_results.csv"
        df.to_csv(csv_path, index=False)
        fam_df = pd.concat(fam_tables, ignore_index=True)
        fam_path = out_dir / "baseline_family_recall.csv"
        fam_df.to_csv(fam_path, index=False)
        log.info("saved %s", csv_path)
        log.info("saved %s", fam_path)

        cols = ["precision", "recall", "f1", "pr_auc", "roc_auc", "fpr", "fnr"]
        for track in ("A1", "A2", "B"):
            sub = df[df["track"] == track]
            log.info("Track %s per-fold table:", track)
            log.info("\n%s", sub[["model", "fold"] + cols + ["train_s", "val_throughput_flows_s"]].round(4).to_string(index=False))
            if track in ("A1", "A2"):
                agg = sub.groupby("model")[cols].agg(["mean", "std"])
                log.info("Track %s mean/std across folds:", track)
                log.info("\n%s", agg.round(4).to_string())

        log.info("Inference timing (measured, model fitted on chronological fold-1 train):")
        for name in args.models:
            r = next(rr for rr in results if rr["model"] == name and rr.get("track") == "A1" and rr.get("fold") == 1)
            log.info("  %-22s throughput=%.0f flows/s  latency median=%.3fms p95=%.3fms",
                     name, r.get("throughput_flows_s", float("nan")),
                     r.get("latency_median_ms", float("nan")), r.get("latency_p95_ms", float("nan")))


if __name__ == "__main__":
    main()