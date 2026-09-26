"""STEP 13 artifact — single-record inference on a previously unseen flow.

Loads the saved calibrated pipeline + threshold and scores ONE flow record
(a dict or JSON string) WITHOUT retraining. No dataset access needed.

Feature contract: the 66 numeric features from reports/feature_dictionary.md
(in canonical order, see models/feature_schema.json). Missing keys -> error;
extra metadata keys are ignored. Values are cast to float32 exactly as during
training (the saved pipeline contains the fitted scaler/selector/model chain).

Usage:
    python src/inference.py --json '{"protocol": 6, "flow_duration_s": 8.9, ...}'
    python src/inference.py --demo          # scores a synthetic record
    python -c "from inference import score_record; print(score_record({...}))"
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

from config import load_config
from feature_engineering import FEATURE_NAMES
from utils import log


def load_model(models_dir: Path):
    """Load calibrated pipeline + thresholds; returns (model, thresholds)."""
    import joblib
    model_path = models_dir / "calibrated_model.joblib"
    th_path = models_dir / "threshold.json"
    if not model_path.exists() or not th_path.exists():
        raise FileNotFoundError(
            f"model artifacts missing in {models_dir} - run src/calibrate.py first")
    model = joblib.load(model_path)
    th = json.loads(th_path.read_text())
    return model, th


def record_to_vector(record: dict) -> np.ndarray:
    """Validate + convert one flow record into the (1, 66) float32 matrix."""
    missing = [f for f in FEATURE_NAMES if f not in record]
    if missing:
        raise ValueError(f"record missing {len(missing)} required features: {missing[:8]} ...")
    vals = []
    for f in FEATURE_NAMES:
        v = record[f]
        if v is None:
            raise ValueError(f"feature {f} is None (NaN not accepted at inference)")
        try:
            fv = float(v)
        except (TypeError, ValueError) as e:
            raise ValueError(f"feature {f}={v!r} is not numeric") from e
        if not np.isfinite(fv):
            raise ValueError(f"feature {f}={fv} is not finite (NaN/inf rejected)")
        vals.append(fv)
    return np.asarray(vals, dtype=np.float32).reshape(1, -1)


def score_record(record: dict, model=None, thresholds: dict | None = None) -> dict:
    """Score ONE unseen flow record. Returns label, probability, threshold used."""
    if model is None or thresholds is None:
        cfg = load_config()
        model, thresholds = load_model(cfg.models_dir)
    x = record_to_vector(record)
    t0 = time.perf_counter()
    proba = float(model.predict_proba(x)[0, 1])
    latency_ms = (time.perf_counter() - t0) * 1e3
    # same operating point as final test (t_op; falls back to t_f1 on old artifacts)
    t_attack = thresholds["thresholds"].get("t_op", thresholds["thresholds"]["t_f1"])
    return {
        "prediction": "attack" if proba >= t_attack else "benign",
        "attack_probability": proba,
        "threshold_used": t_attack,
        "latency_ms": round(latency_ms, 3),
    }


# Real flow record (measured, from data/processed/flows — benign IDP capture):
# one-way UDP-heavy flow: 10,862 packets @ ~554.6 B, 0.9 ms mean IAT, 10 s duration.
DEMO_RECORD = {
    "protocol": 17.0, "flow_duration_s": 9.9988, "fwd_packets": 10862.0,
    "bwd_packets": 0.0, "fwd_bytes": 6023964.0, "bwd_bytes": 0.0,
    "fwd_len_max": 558.0, "fwd_len_min": 554.0, "fwd_len_mean": 554.5907,
    "fwd_len_std": 1.4192, "bwd_len_max": 0.0, "bwd_len_min": 0.0,
    "bwd_len_mean": 0.0, "bwd_len_std": 0.0, "pkt_len_max": 558.0,
    "pkt_len_min": 554.0, "pkt_len_mean": 554.5907, "pkt_len_std": 1.4192,
    "flow_iat_mean": 0.0009, "flow_iat_std": 0.0004, "flow_iat_max": 0.008,
    "flow_iat_min": 0.0, "fwd_iat_total": 9.9988, "fwd_iat_mean": 0.0009,
    "fwd_iat_std": 0.0004, "fwd_iat_max": 0.008, "fwd_iat_min": 0.0,
    "bwd_iat_total": 0.0, "bwd_iat_mean": 0.0, "bwd_iat_std": 0.0,
    "bwd_iat_max": 0.0, "bwd_iat_min": 0.0, "fwd_psh": 0.0, "bwd_psh": 0.0,
    "fwd_urg": 0.0, "bwd_urg": 0.0, "fin_count": 0.0, "syn_count": 0.0,
    "rst_count": 0.0, "psh_count": 0.0, "ack_count": 0.0, "urg_count": 0.0,
    "ece_count": 0.0, "cwr_count": 0.0, "fwd_header_bytes": 304136.0,
    "bwd_header_bytes": 0.0, "down_up_ratio": 0.0, "avg_pkt_size": 554.5907,
    "avg_fwd_seg": 554.5907, "avg_bwd_seg": 0.0, "init_fwd_win": 0.0,
    "init_bwd_win": 0.0, "fwd_data_pkts": 10862.0, "bwd_data_pkts": 0.0,
    "active_mean": 9.9988, "active_std": 0.0, "active_max": 9.9988,
    "active_min": 9.9988, "idle_mean": 0.0, "idle_std": 0.0, "idle_max": 0.0,
    "idle_min": 0.0, "flow_bytes_s": 602467.75, "flow_packets_s": 1086.3286,
    "fwd_win_mean": 0.0, "bwd_win_mean": 0.0,
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=str, default=None, help="flow record as JSON string")
    ap.add_argument("--file", type=str, default=None, help="flow record as JSON file")
    ap.add_argument("--demo", action="store_true", help="score the built-in demo record")
    args = ap.parse_args()

    if args.demo:
        record = DEMO_RECORD
    elif args.json:
        record = json.loads(args.json)
    elif args.file:
        record = json.loads(Path(args.file).read_text(encoding="utf-8"))
    else:
        ap.error("one of --json / --file / --demo is required")

    model, thresholds = load_model(load_config().models_dir)
    result = score_record(record, model=model, thresholds=thresholds)
    print(json.dumps(result, indent=2))
    log.info("single-record inference complete")


if __name__ == "__main__":
    main()
