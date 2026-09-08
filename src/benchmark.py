"""STEP 13 — Inference benchmark for the final saved model.

Measures (on the untouched final-test feature matrix, never used for training
or selection — reading it here for benchmarking is the STEP 12/13 sequence):
  * batch throughput (flows/s) at several batch sizes
  * single-record latency (median / p95 / p99, ms) over 500 calls
  * warm-vs-cold start (first-call overhead)
  * model size on disk

Results -> reports/inference_benchmark.md + experiments/benchmark.csv
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

from config import load_config
from data_loader import load_flows
from inference import load_model
from split import build_manifest
from utils import log, timed_stage


def main() -> None:
    cfg = load_config()
    with timed_stage(1, 4, "Loading final-test feature matrix (benchmark only)"):
        m = build_manifest(cfg)
        test_caps = m[m["track_a_role"] == "final_test"]["capture"].tolist()
        X, y, meta = load_flows(test_caps, cfg.processed_dir / "flows")
        log.info("final test: %s flows from %d captures", f"{len(y):,}", len(test_caps))

    with timed_stage(2, 4, "Loading calibrated model"):
        model, th = load_model(cfg.models_dir)
        t_f1 = th["thresholds"].get("t_op", th["thresholds"]["t_f1"])

    with timed_stage(3, 4, "Benchmarking"):
        rows = []
        # cold start (first call includes lazy allocations)
        t0 = time.perf_counter()
        _ = model.predict_proba(X[:1])
        cold_ms = (time.perf_counter() - t0) * 1e3
        rows.append({"metric": "cold_start_ms", "value": round(cold_ms, 3)})

        # batch throughput at several sizes
        for bs in (1_000, 10_000, 100_000):
            t0 = time.perf_counter()
            _ = model.predict_proba(X[:bs])
            s = time.perf_counter() - t0
            rows.append({"metric": f"throughput_flows_s@{bs}", "value": round(bs / s, 0)})

        # full-matrix throughput
        t0 = time.perf_counter()
        proba = model.predict_proba(X)[:, 1]
        full_s = time.perf_counter() - t0
        rows.append({"metric": "throughput_flows_s@full", "value": round(len(X) / full_s, 0)})

        # single-row latency distribution (500 calls)
        rng = np.random.default_rng(cfg.random_seed)
        idx = rng.integers(0, len(X), size=500)
        lat = []
        for i in idx:
            t0 = time.perf_counter()
            _ = model.predict_proba(X[i:i + 1])
            lat.append((time.perf_counter() - t0) * 1e3)
        lat = np.asarray(lat)
        rows += [
            {"metric": "latency_median_ms", "value": round(float(np.median(lat)), 3)},
            {"metric": "latency_mean_ms", "value": round(float(lat.mean()), 3)},
            {"metric": "latency_p95_ms", "value": round(float(np.percentile(lat, 95)), 3)},
            {"metric": "latency_p99_ms", "value": round(float(np.percentile(lat, 99)), 3)},
        ]

        # model size
        size_mb = (cfg.models_dir / "calibrated_model.joblib").stat().st_size / 1e6
        rows.append({"metric": "model_size_mb", "value": round(size_mb, 2)})

        # accuracy at the selected operating threshold (context for the benchmark)
        pred = (proba >= t_f1).astype(np.int64)
        acc = float((pred == y).mean())
        rows.append({"metric": "accuracy_at_operating_threshold", "value": round(acc, 6)})

        bdf = pd.DataFrame(rows)
        bdf.to_csv(cfg.experiments_dir / "benchmark.csv", index=False)

    with timed_stage(4, 4, "Writing benchmark report"):
        lines = [
            "# Inference Benchmark (STEP 13)", "",
            f"**Model:** calibrated pipeline from `models/calibrated_model.joblib` · "
            f"**Data:** untouched final test ({len(y):,} flows, {len(test_caps)} captures)", "",
            "| Metric | Value |", "|---|---:|",
        ]
        for _, r in bdf.iterrows():
            lines.append(f"| {r['metric']} | {r['value']} |")
        lines += ["", f"Operating threshold: {t_f1:.6f}", ""]
        (Path(cfg.reports_dir) / "inference_benchmark.md").write_text(
            "\n".join(lines), encoding="utf-8")
        log.info("saved %s", Path(cfg.reports_dir) / "inference_benchmark.md")
        log.info("\n%s", bdf.to_string(index=False))


if __name__ == "__main__":
    main()
