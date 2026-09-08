"""ANALYSIS 4 — Threshold / operational cost sensitivity (DEVELOPMENT ONLY).

The deployed threshold is FROZEN at t=0.5. This analysis only maps the
tradeoff landscape around it on development validation data, so the choice is
defensible: recall/FPR/FN/FP at each threshold, plus the three reference
points (FPR<=1e-3 region, recall-max under that cap, F1-max).

Data: the frozen model's probabilities on the A-2 calibration split used by
src/calibrate.py (fit = fold-5 train window, calibration = fold-5 val
captures) — dev-only, capture-disjoint, identical construction. The final
test is never touched and threshold.json is never modified.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from config import load_config  # noqa: E402
from research_utils import (  # noqa: E402
    RESEARCH_DIR, a2_folds, dev_data, evaluate_at_threshold, frozen_model,
    json_dump,
)
from utils import log, set_seeds, timed_stage  # noqa: E402

GRID = [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]


def calib_split(X, y, meta, dev_caps):
    """Replicate calibrate.py's fold-5 fit/calibration split exactly."""
    groups = meta["capture_file"].to_numpy()
    folds, used_seed = a2_folds(dev_caps, groups, y)
    tr, va = folds[4]  # fold 5, same as calibration
    fit_caps = set(np.unique(groups[tr]))
    cal_caps = set(np.unique(groups[va]))
    assert not (fit_caps & cal_caps), "calibration/fit capture overlap"
    return np.where(np.isin(groups, list(fit_caps)))[0], \
        np.where(np.isin(groups, list(cal_caps)))[0], used_seed


def main() -> None:
    set_seeds(42)
    t0 = time.perf_counter()

    with timed_stage(1, 3, "Loading dev data + frozen model; rebuilding cal split"):
        X, y, meta, m = dev_data()
        dev_caps = m[m["track_a_role"] != "final_test"]["capture"].tolist()
        model = frozen_model()
        fit_idx, cal_idx, used_seed = calib_split(X, y, meta, dev_caps)
        log.info("cal split: fit=%s flows / cal=%s flows (seed offset %d)",
                 f"{len(fit_idx):,}", f"{len(cal_idx):,}", used_seed)

    with timed_stage(2, 3, "Scoring calibration split with the FROZEN pipeline"):
        # NOTE: no refitting — the frozen artifact is applied as-is. The
        # calibration captures are held out from fold-5's train window by
        # construction, so these probabilities are honest out-of-sample.
        proba = model.predict_proba(X.iloc[cal_idx])[:, 1]
        y_cal = y[cal_idx]
        meta_cal = meta.iloc[cal_idx].reset_index(drop=True)

    with timed_stage(3, 3, "Threshold grid evaluation"):
        rows = []
        for t in GRID:
            r = evaluate_at_threshold(y_cal, proba, t)
            r["threshold"] = t
            r["cost_fp_per_1k_benign"] = round(r["fpr"] * 1000, 3)
            r["missed_attacks"] = r["fn"]
            rows.append(r)
        df = pd.DataFrame(rows)

        fpr_target = 1e-3
        ok = df[df["fpr"] <= fpr_target]
        best_recall_row = ok.loc[ok["recall"].idxmax()] if len(ok) else None
        best_f1_row = df.loc[df["f1"].idxmax()]
        deployed = df[np.isclose(df["threshold"], 0.5)].iloc[0]

        out = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "seed": 42,
            "scope": "development calibration split only; frozen model; "
                     "threshold.json NOT modified; final test untouched",
            "calibration_split": {
                "n_fit_flows": int(len(fit_idx)), "n_cal_flows": int(len(cal_idx)),
                "n_cal_benign": int((y_cal == 0).sum()),
                "n_cal_attack": int((y_cal == 1).sum()),
                "fold_seed_offset": int(used_seed),
            },
            "grid": df.to_dict(orient="records"),
            "reference_points": {
                "deployed_t_0.5": {
                    "precision": float(deployed["precision"]),
                    "recall": float(deployed["recall"]),
                    "f1": float(deployed["f1"]),
                    "fpr": float(deployed["fpr"]),
                    "fn": int(deployed["fn"]), "fp": int(deployed["fp"]),
                },
                "fpr_le_1e-3_achievable": bool(len(ok) > 0),
                "max_recall_with_fpr_le_1e-3": {
                    "threshold": float(best_recall_row["threshold"]),
                    "recall": float(best_recall_row["recall"]),
                    "fpr": float(best_recall_row["fpr"]),
                } if best_recall_row is not None else None,
                "max_f1": {
                    "threshold": float(best_f1_row["threshold"]),
                    "f1": float(best_f1_row["f1"]),
                },
            },
            "note": "analysis only — the deployed operating point remains t=0.5",
        }
        json_dump(out, Path("reports/threshold_sensitivity_results.json"))
        df.to_csv(RESEARCH_DIR / "threshold_sensitivity_results.csv", index=False)

        log.info("\n%s", df[["threshold", "precision", "recall", "f1", "fpr",
                             "fnr", "fp", "fn"]].round(5).to_string(index=False))
        log.info("ANALYSIS 4 DONE in %.1fs", time.perf_counter() - t0)


if __name__ == "__main__":
    main()
