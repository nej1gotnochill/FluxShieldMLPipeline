"""STEP 12 — Untouched final test.

Runs EXACTLY ONCE: loads models/calibrated_model.joblib + threshold.json
(both frozen before this step) and scores the final-test captures (May 4-6,
15 captures, 442,521 flows). No training, no tuning, no threshold changes,
no calibration here — this module only measures.

Outputs:
  experiments/final_test_results.csv   (aggregate + per-family + per-capture)
  reports/final_test_report.md
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from config import load_config
from data_loader import load_flows
from evaluate import evaluate_binary, measure_inference, per_family_metrics
from inference import load_model
from split import build_manifest, verify_manifest
from utils import log, set_seeds, timed_stage


def main() -> None:
    cfg = load_config()
    set_seeds(cfg.random_seed)

    with timed_stage(1, 4, "Loading final-test captures (first and only access)"):
        m = build_manifest(cfg)
        if not verify_manifest(m):
            sys.exit(1)
        test_caps = m[m["track_a_role"] == "final_test"]["capture"].tolist()
        X, y, meta = load_flows(test_caps, cfg.processed_dir / "flows")
        log.info("final test: %s flows, %d captures, benign=%s attack=%s",
                 f"{len(y):,}", len(test_caps), f"{int((y==0).sum()):,}",
                 f"{int((y==1).sum()):,}")
        if len(y) == 0 or len(np.unique(y)) < 2:
            log.error("final test must contain both classes - aborting")
            sys.exit(1)

    with timed_stage(2, 4, "Loading frozen artifacts (calibrated model + threshold)"):
        model, th = load_model(cfg.models_dir)
        # t_op = validated operating point (STEP 11); fall back to t_f1 on old artifacts
        t_op = th["thresholds"].get("t_op", th["thresholds"]["t_f1"])
        log.info("operating threshold (frozen at STEP 11): %.6f", t_op)
        log.info("calibrator: %s | model: %s", th.get("calibrator"), th.get("model"))

    with timed_stage(3, 4, "Scoring final test (single pass)"):
        t0 = time.perf_counter()
        proba = model.predict_proba(X)[:, 1]
        infer_s = time.perf_counter() - t0
        pred = (proba >= t_op).astype(np.int64)
        agg = evaluate_binary(y, pred, proba)
        log.info("FINAL TEST: P=%.4f R=%.4f F1=%.4f PR-AUC=%.4f ROC=%.4f FPR=%.5f FNR=%.5f",
                 agg["precision"], agg["recall"], agg["f1"], agg["pr_auc"],
                 agg["roc_auc"], agg["fpr"], agg["fnr"])

        fam = per_family_metrics(meta, y, pred, proba)
        # per-capture table
        cap_rows = []
        cap_vals = meta["capture_file"].to_numpy()
        for cap in np.unique(cap_vals):
            i = np.where(cap_vals == cap)[0]
            cm = evaluate_binary(y[i], pred[i], proba[i])
            cap_rows.append({"capture": str(cap), "family": str(meta["family"].iloc[i[0]]),
                             "n_flows": len(i), "recall": cm["recall"],
                             "fpr": cm["fpr"], "fnr": cm["fnr"],
                             "n_benign": cm["n_benign"], "n_attack": cm["n_attack"]})
        cap_df = pd.DataFrame(cap_rows)
        timing = measure_inference(model, X)

    with timed_stage(4, 4, "Saving final-test results + report"):
        out = Path(cfg.experiments_dir)
        pd.DataFrame([{**agg, "threshold": t_op, "infer_s": round(infer_s, 2),
                       **timing}]).to_csv(out / "final_test_results.csv", index=False)
        fam.to_csv(out / "final_test_family_recall.csv", index=False)
        cap_df.to_csv(out / "final_test_per_capture.csv", index=False)

        lines = [
            "# Final Test Report (STEP 12) — untouched May 4-6 captures", "",
            f"**Flows:** {len(y):,} ({int((y==0).sum()):,} benign / {int((y==1).sum()):,} attack) · "
            f"**Captures:** {len(test_caps)} · **Threshold:** {t_op:.6f} (frozen, validated op point) · "
            f"**Calibrator:** {th.get('calibrator')}", "",
            "| Metric | Value |", "|---|---:|",
            f"| Precision | {agg['precision']:.4f} |",
            f"| Recall | {agg['recall']:.4f} |",
            f"| F1 | {agg['f1']:.4f} |",
            f"| PR-AUC | {agg['pr_auc']:.4f} |",
            f"| ROC-AUC | {agg['roc_auc']:.4f} |",
            f"| FPR | {agg['fpr']:.5f} ({agg['fp']:,} of {agg['n_benign']:,} benign) |",
            f"| FNR | {agg['fnr']:.5f} ({agg['fn']:,} of {agg['n_attack']:,} attack) |",
            f"| Confusion (tn, fp, fn, tp) | {agg['tn']:,}, {agg['fp']:,}, {agg['fn']:,}, {agg['tp']:,} |",
            "", "## Per attack family", "",
            "| Family | Flows | Recall | Mean proba |", "|---|---:|---:|---:|",
        ]
        for _, r in fam.iterrows():
            lines.append(f"| {r['family']} | {r['n_flows']:,} | {r['recall']:.4f} | "
                         f"{r['mean_proba']:.4f} |")
        lines += ["", "## Per capture", "",
                  "| Capture | Family | Flows | Recall | FPR |", "|---|---|---:|---:|---:|"]
        for _, r in cap_df.iterrows():
            lines.append(f"| {r['capture']} | {r['family']} | {r['n_flows']:,} | "
                         f"{r['recall']:.4f} | {r['fpr']:.5f} |")
        lines += ["", f"Inference: {timing['throughput_flows_s']:.0f} flows/s, "
                  f"latency median {timing['latency_median_ms']:.2f} ms / "
                  f"p95 {timing['latency_p95_ms']:.2f} ms", ""]
        (Path(cfg.reports_dir) / "final_test_report.md").write_text(
            "\n".join(lines), encoding="utf-8")
        log.info("saved final_test_results.csv, final_test_family_recall.csv, "
                 "final_test_per_capture.csv, reports/final_test_report.md")


if __name__ == "__main__":
    main()
