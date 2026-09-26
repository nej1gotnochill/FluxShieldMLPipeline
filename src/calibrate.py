"""STEPS 10-11 — Probability calibration + decision-threshold selection.

Everything here uses DEVELOPMENT data only (Track A-2 folds). The final test
(May 4-6 captures) is NEVER loaded.

Design
------
[1/5] Load best tuned config from experiments/tuning_results.csv
      (highest mean PR-AUC, tie-break lowest mean FNR).
[2/5] Fit the tuned model on A-2 folds 1-4 training windows;
      fold 5's VALIDATION captures become the calibration set.
      (Capture-disjoint by construction: fold-5 val captures never appear in
      folds 1-4 training windows.)
[3/5] Calibrate with CalibratedClassifierCV(cv="prefit", method=<isotonic|sigmoid>).
      Both are fitted and compared on the calibration fold; better Brier/ECE wins.
[4/5] Threshold selection on the SAME calibration fold (never test):
        * t_f1   : maximizes F1
        * t_fpr  : highest-recall threshold with FPR <= target (default 1e-3)
        * t_youden : maximizes recall + specificity (Youden's J)
      All three are reported; the operating point choice is recorded in metadata.
[5/5] Save calibration artifacts:
        models/calibrated_model.joblib   (pipeline + calibrator)
        models/threshold.json            (thresholds + selection metrics)
        reports/calibration_report.md

Hard rules honoured:
  * calibration data = A-2 fold-5 validation captures (dev only)
  * thresholds chosen on the calibration fold, never on final test
  * no final-test access
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import brier_score_loss

from config import load_config
from data_loader import load_flows
from evaluate import evaluate_binary, per_family_metrics
from split import TRACK_A_FOLDS, build_manifest, verify_manifest
from train import make_group_folds
from tune import build_model, param_sig
from utils import log, set_seeds, timed_stage


def ece_score(y_true: np.ndarray, proba: np.ndarray, n_bins: int = 15) -> float:
    """Expected Calibration Error (equal-width bins)."""
    bins = np.clip((proba * n_bins).astype(int), 0, n_bins - 1)
    ece = 0.0
    for b in range(n_bins):
        mask = bins == b
        if not mask.any():
            continue
        conf = proba[mask].mean()
        acc = y_true[mask].mean()
        ece += mask.mean() * abs(acc - conf)
    return float(ece)


def pick_thresholds(y_true: np.ndarray, proba: np.ndarray, fpr_target: float = 1e-3) -> dict:
    """Threshold candidates computed ONLY on calibration data."""
    order = np.argsort(-proba)
    p_sorted = proba[order]
    y_sorted = y_true[order]
    tp = np.cumsum(y_sorted)
    fp = np.cumsum(1 - y_sorted)
    n_pos, n_neg = max(int(tp[-1]), 1), max(int(fp[-1]), 1)
    fn = n_pos - tp
    tn = n_neg - fp
    prec = tp / np.maximum(tp + fp, 1)
    rec = tp / n_pos
    f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
    j = rec + tn / n_neg - 1.0

    t_f1 = float(p_sorted[int(np.argmax(f1))])
    ok = (fp / n_neg) <= fpr_target
    if ok.any():
        # highest-recall threshold meeting the FPR cap
        i = int(np.where(ok)[0][-1])
        t_fpr = float(p_sorted[i])
        fpr_at = float(fp[i] / n_neg)
        rec_at = float(rec[i])
    else:
        t_fpr = float(p_sorted[-1])
        fpr_at, rec_at = 1.0, 1.0
    t_j = float(p_sorted[int(np.argmax(j))])
    return {
        "t_f1": t_f1, "t_fpr": t_fpr, "t_youden": t_j,
        "f1_at_t_f1": float(f1[int(np.argmax(f1))]),
        "fpr_at_t_fpr": fpr_at, "recall_at_t_fpr": rec_at,
        "recall_at_t_f1": float(rec[int(np.argmax(f1))]),
        "j_at_t_youden": float(j[int(np.argmax(j))]),
        "fpr_target": fpr_target,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--method", choices=["auto", "isotonic", "sigmoid"], default="auto")
    ap.add_argument("--fpr-target", type=float, default=1e-3,
                    help="FPR cap for the recall-maximizing threshold")
    ap.add_argument("--cal-folds", type=int, nargs="+", default=[5],
                    help="which A-2 fold(s) form the calibration set")
    ap.add_argument("--trial-id", type=str, default=None,
                    help="pin an exact tuning trial (e.g. 4fc1eda5-ex-019); "
                         "default: best by mean PR-AUC then mean FNR")
    args = ap.parse_args()

    cfg = load_config()
    set_seeds(cfg.random_seed)

    with timed_stage(1, 5, "Loading best tuned config"):
        csv_path = Path(cfg.experiments_dir) / "tuning_results.csv"
        if not csv_path.exists():
            log.error("tuning_results.csv missing - run src/tune.py first")
            sys.exit(1)
        df = pd.read_csv(csv_path)
        if args.trial_id:
            row = df[df["trial_id"] == args.trial_id]
            if row.empty:
                log.error("trial %s not found in %s", args.trial_id, csv_path)
                sys.exit(1)
            row = row.iloc[0]
        else:
            row = df.sort_values(["mean_pr_auc", "mean_fnr"],
                                 ascending=[False, True]).iloc[0]
        model_name, params = row["model"], eval(row["params"])
        log.info("selected config: %s (%s) | %s (mean PR-AUC %.6f)",
                 model_name, row["trial_id"], row["params"], row["mean_pr_auc"])

    with timed_stage(2, 5, "Loading development flows + rebuilding folds"):
        m = build_manifest(cfg)
        if not verify_manifest(m):
            sys.exit(1)
        dev_caps = m[m["track_a_role"] != "final_test"]["capture"].tolist()
        X, y, meta = load_flows(dev_caps, cfg.processed_dir / "flows")
        groups = meta["capture_file"].to_numpy()
        folds, used_seed = make_group_folds(dev_caps, groups, y, n_splits=5, seed0=cfg.random_seed)
        log.info("folds rebuilt with seed offset %d (identical to baselines/tuning)", used_seed)

        cal_folds = set(args.cal_folds)
        fit_idx: list[np.ndarray] = []
        cal_idx: list[np.ndarray] = []
        for fi, (tr, va) in enumerate(folds, start=1):
            if fi in cal_folds:
                # fit on THIS fold's training window (excludes its val captures by
                # GroupKFold construction); the fold's val captures = calibration data.
                # NOTE: other folds' training windows contain the calibration captures
                # (cross-validation design), so they must NOT be used here.
                fit_idx.append(tr)
                cal_idx.append(va)
        fit_all = np.unique(np.concatenate(fit_idx))
        cal_all = np.concatenate(cal_idx)
        # safety: calibration captures must not appear in fit captures
        fit_caps = set(np.unique(groups[fit_all]))
        cal_caps = set(np.unique(groups[cal_all]))
        overlap = fit_caps & cal_caps
        if overlap:
            log.error("calibration/fit capture overlap: %s", overlap)
            sys.exit(1)
        log.info("fit captures=%d (%s flows) | calibration captures=%d (%s flows)",
                 len(fit_caps), f"{len(fit_all):,}", len(cal_caps), f"{len(cal_all):,}")
        X_fit, y_fit = X.iloc[fit_all], y[fit_all]
        X_cal, y_cal = X.iloc[cal_all], y[cal_all]
        meta_cal = meta.iloc[cal_all]

    with timed_stage(3, 5, "Fitting tuned model + calibrators"):
        t0 = time.perf_counter()
        base = build_model(model_name, params, cfg.random_seed)
        base.fit(X_fit, y_fit)
        fit_s = time.perf_counter() - t0
        log.info("base model fitted in %.1fs", fit_s)

        raw_proba = base.predict_proba(X_cal)[:, 1]
        raw_brier = float(brier_score_loss(y_cal, raw_proba))
        raw_ece = ece_score(y_cal, raw_proba)
        log.info("uncalibrated: Brier=%.6f ECE=%.6f", raw_brier, raw_ece)

        cands = {}
        if args.method in ("auto", "isotonic"):
            t0 = time.perf_counter()
            iso = CalibratedClassifierCV(base, method="isotonic", cv="prefit")
            iso.fit(X_cal, y_cal)
            p = iso.predict_proba(X_cal)[:, 1]
            cands["isotonic"] = (brier_score_loss(y_cal, p), ece_score(y_cal, p),
                                 iso, time.perf_counter() - t0)
        if args.method in ("auto", "sigmoid"):
            t0 = time.perf_counter()
            sig = CalibratedClassifierCV(base, method="sigmoid", cv="prefit")
            sig.fit(X_cal, y_cal)
            p = sig.predict_proba(X_cal)[:, 1]
            cands["sigmoid"] = (brier_score_loss(y_cal, p), ece_score(y_cal, p),
                                sig, time.perf_counter() - t0)
        for name, (b, e, _, s) in cands.items():
            log.info("calibrated[%s]: Brier=%.6f ECE=%.6f (%.1fs)", name, b, e, s)
        # Degeneracy guard: on a near-separable fold, isotonic collapses to a
        # step function (few distinct outputs) -> no threshold resolution and
        # t_f1 pins to 1.0, which Track B showed destroys unseen-family recall.
        # Prefer the calibrator that preserves resolution unless its loss is far worse.
        def n_resolved(mdl):
            p = mdl.predict_proba(X_cal)[:, 1]
            return len(np.unique(p)), int(((p > 0.001) & (p < 0.999)).sum())
        iso_dist = n_resolved(cands["isotonic"][2])[0] if "isotonic" in cands else 0
        sig_dist = n_resolved(cands["sigmoid"][2])[0] if "sigmoid" in cands else 0
        method = min(cands, key=lambda k: (cands[k][0] + cands[k][1]))
        if iso_dist <= 10 and sig_dist > iso_dist:
            log.warning("isotonic degenerate (%d distinct outputs) - selecting sigmoid "
                        "for threshold resolution (Track B informed)", iso_dist)
            method = "sigmoid"
        cal_brier, cal_ece, calibrated_model, cal_s = cands[method]
        log.info("selected calibrator: %s (distinct outputs: iso=%d sig=%d)",
                 method, iso_dist, sig_dist)

    with timed_stage(4, 5, "Threshold selection (dev-benign-validated)"):
        cal_proba = calibrated_model.predict_proba(X_cal)[:, 1]
        th = pick_thresholds(y_cal, cal_proba, fpr_target=args.fpr_target)
        log.info("data-fitted thresholds on calibration fold: t_f1=%.6f | t_fpr=%.6f | "
                 "t_youden=%.6f", th["t_f1"], th["t_fpr"], th["t_youden"])

        # The calibration fold is near-separable, so data-fitted thresholds pin to
        # the extremes (documented degeneracy). The operating point is therefore
        # the standard t=0.5, VALIDATED on held-out dev benign flows (fold-5 val
        # never seen by the base model). If it misses the FPR target, walk it up.
        ben_mask_cal = (y_cal == 0)
        fpr_at = lambda t: float((cal_proba[ben_mask_cal] >= t).mean())
        t_op = 0.5
        if fpr_at(t_op) > args.fpr_target:
            for t in np.arange(0.5, 0.99, 0.01):
                if fpr_at(float(t)) <= args.fpr_target:
                    t_op = float(t)
                    break
        log.info("operating threshold t_op=%.2f | held-out dev-benign FPR=%.5f "
                 "(target %.1e) | recall on cal fold=%.4f",
                 t_op, fpr_at(t_op), args.fpr_target,
                 float((cal_proba[y_cal == 1] >= t_op).mean()))
        th["t_op"] = t_op
        th["fpr_at_t_op"] = fpr_at(t_op)
        th["op_point_rationale"] = (
            "t=0.5 default; calibration fold near-separable so data-fitted "
            "thresholds are degenerate; validated against held-out dev benign "
            "FPR and Track B unseen-family recall (reports/tuning_report.md)")

        # metrics at each candidate threshold on the calibration fold
        per_th = {}
        for name in ("t_f1", "t_fpr", "t_youden", "t_op"):
            pred = (cal_proba >= th[name]).astype(np.int64)
            per_th[name] = evaluate_binary(y_cal, pred, cal_proba)

    with timed_stage(5, 5, "Saving calibration artifacts"):
        models_dir = Path(cfg.models_dir)
        models_dir.mkdir(parents=True, exist_ok=True)
        import joblib
        joblib.dump(calibrated_model, models_dir / "calibrated_model.joblib")

        meta_out = {
            "model": model_name,
            "params": params,
            "calibrator": method,
            "calibration_brier": cal_brier,
            "calibration_ece": cal_ece,
            "uncalibrated_brier": raw_brier,
            "uncalibrated_ece": raw_ece,
            "calibration_captures": sorted(cal_caps),
            "fit_captures": sorted(fit_caps),
            "thresholds": th,
            "threshold_metrics_on_calibration_fold": per_th,
            "fpr_target": args.fpr_target,
            "random_seed": cfg.random_seed,
            "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        (models_dir / "threshold.json").write_text(json.dumps(meta_out, indent=2))
        log.info("saved %s and %s", models_dir / "calibrated_model.joblib",
                 models_dir / "threshold.json")

        # markdown report
        lines = [
            "# Calibration & Threshold Report (STEPS 10-11)", "",
            f"**Model:** `{model_name}` · **Calibrator:** {method} · "
            f"**Calibration data:** A-2 fold(s) {sorted(cal_folds)} validation captures "
            f"({len(cal_caps)} captures, {len(y_cal):,} flows) · final test untouched", "",
            "| Calibrator | Brier | ECE |",
            "|---|---:|---:|",
            f"| uncalibrated | {raw_brier:.6f} | {raw_ece:.6f} |",
            f"| isotonic | {cands['isotonic'][0]:.6f} | {cands['isotonic'][1]:.6f} |"
            if "isotonic" in cands else None,
            f"| sigmoid | {cands['sigmoid'][0]:.6f} | {cands['sigmoid'][1]:.6f} |"
            if "sigmoid" in cands else None,
            "", "## Threshold candidates (calibration fold only)", "",
            "| Point | Threshold | Precision | Recall | F1 | FPR | FNR |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for name, mm in per_th.items():
            lines.append(
                f"| {name} ({th[name]:.4f}) | {th[name]:.6f} | {mm['precision']:.4f} | "
                f"{mm['recall']:.4f} | {mm['f1']:.4f} | {mm['fpr']:.5f} | {mm['fnr']:.5f} |")
        lines += ["", f"FPR target for t_fpr: {args.fpr_target}", ""]
        rep = "\n".join([l for l in lines if l is not None])
        (Path(cfg.reports_dir) / "calibration_report.md").write_text(rep, encoding="utf-8")
        log.info("saved %s", Path(cfg.reports_dir) / "calibration_report.md")

    log.info("CALIBRATION DONE — next: untouched final test (STEP 12) on approval.")


if __name__ == "__main__":
    main()
