"""STEP 14 — Save the complete model artifact metadata.

Composes (after calibration, before/with the final test):
  models/feature_schema.json   — exact ordered feature list, dtypes, units,
                                 online/terminal availability, metadata columns
  models/model_metadata.json   — dataset path/version, split captures, model +
                                 params, calibrator, threshold, seed, software
                                 versions, training timestamp

Everything is read from artifacts already on disk (split manifest, threshold
json, tuning results) — nothing is recomputed or invented.
"""
from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn

from config import load_config
from feature_engineering import FEATURE_NAMES, META_COLUMNS
from split import build_manifest, verify_manifest
from utils import log

# feature availability classification (see reports/feature_dictionary.md):
# ONLINE  = computable while the flow is still active
# TERMINAL = requires flow end / full packet sequence
ONLINE_FEATURES = {
    "protocol", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "fwd_len_max", "fwd_len_min", "fwd_len_mean", "fwd_len_std",
    "bwd_len_max", "bwd_len_min", "bwd_len_mean", "bwd_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_max", "fwd_iat_min", "fwd_iat_std",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_max", "bwd_iat_min", "bwd_iat_std",
    "fwd_psh", "bwd_psh", "fwd_urg", "bwd_urg",
    "fin_count", "syn_count", "rst_count", "psh_count", "ack_count",
    "urg_count", "ece_count", "cwr_count",
    "fwd_header_bytes", "bwd_header_bytes", "down_up_ratio",
    "avg_pkt_size", "avg_fwd_seg", "avg_bwd_seg",
    "fwd_data_pkts", "bwd_data_pkts",
    "flow_bytes_s", "flow_packets_s", "fwd_win_mean", "bwd_win_mean",
}
UNITS_SECONDS = {n for n in FEATURE_NAMES if n.endswith("_s") or "_iat" in n
                 or "active" in n or "idle" in n}
UNITS_BYTES = {n for n in FEATURE_NAMES if "bytes" in n}


def main() -> None:
    cfg = load_config()
    models_dir = Path(cfg.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)

    # ---- feature schema -----------------------------------------------------
    schema = {
        "n_features": len(FEATURE_NAMES),
        "features": [
            {
                "name": f,
                "dtype": "float32",
                "units": ("seconds" if f in UNITS_SECONDS
                          else "bytes" if f in UNITS_BYTES
                          else "count" if any(t in f for t in ("packets", "psh", "urg",
                                                               "syn", "fin", "rst"))
                          else "ratio_or_rate"),
                "availability": "ONLINE" if f in ONLINE_FEATURES else "TERMINAL",
            }
            for f in FEATURE_NAMES
        ],
        "metadata_columns": list(META_COLUMNS),
        "metadata_note": ("metadata is joined for analysis ONLY; it is never fed to the "
                          "model (leakage rule: no IPs, ports, timestamps, capture ids)"),
        "definitions": "reports/feature_dictionary.md",
    }
    (models_dir / "feature_schema.json").write_text(json.dumps(schema, indent=2))
    log.info("saved %s (%d features)", models_dir / "feature_schema.json", len(FEATURE_NAMES))

    # ---- model metadata -----------------------------------------------------
    m = build_manifest(cfg)
    if not verify_manifest(m):
        sys.exit(1)
    th_path = models_dir / "threshold.json"
    if not th_path.exists():
        log.error("threshold.json missing - run src/calibrate.py first")
        sys.exit(1)
    th = json.loads(th_path.read_text())

    roles = {"train": [], "val": [], "final_test": []}
    for _, r in m.iterrows():
        if r["track_a_role"] == "train":
            roles["train"].append(r["capture"])
        elif r["track_a_role"] == "val":
            roles["val"].append(r["capture"])
        else:
            roles["final_test"].append(r["capture"])

    tune_csv = Path(cfg.experiments_dir) / "tuning_results.csv"
    best_params, best_scores = None, None
    if tune_csv.exists():
        df = pd.read_csv(tune_csv)
        row = df.sort_values(["mean_pr_auc", "mean_fnr"], ascending=[False, True]).iloc[0]
        best_params, best_scores = row["params"], {
            "mean_pr_auc": float(row["mean_pr_auc"]),
            "mean_recall": float(row["mean_recall"]),
            "mean_fpr": float(row["mean_fpr"]),
            "mean_fnr": float(row["mean_fnr"]),
        }

    import dpkt  # noqa: F401  (version reporting only)
    meta = {
        "dataset": {
            "name": "DDoS-AT-2022",
            "path": str(cfg.dataset_path),
            "flow_table": str(cfg.processed_dir / "flows"),
            "n_flows_total": int(m["n_flows"].sum()),
            "n_captures_total": int(len(m)),
        },
        "splits": {
            "track_a_train_captures": roles["train"],
            "track_a_validation_captures": roles["val"],
            "track_a_final_test_captures": roles["final_test"],
            "track_b_holdout_families": ["tcp_syn_flood", "tcp_rst", "udp_flood"],
            "capture_disjoint": True,
            "final_test_untouched_until_step12": True,
        },
        "model": {
            "name": th.get("model"),
            "params": th.get("params"),
            "search_best_scores": best_scores,
            "calibrator": th.get("calibrator"),
            "calibration_brier": th.get("calibration_brier"),
            "calibration_ece": th.get("calibration_ece"),
        },
        "threshold": th.get("thresholds"),
        "random_seed": cfg.random_seed,
        "trained_at": th.get("trained_at"),
        "exported_at": pd.Timestamp.utcnow().isoformat(),
        "software_versions": {
            "python": platform.python_version(),
            "sklearn": sklearn.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "dpkt": dpkt.__version__,
            "platform": platform.platform(),
        },
        "artifacts": {
            "calibrated_model": "models/calibrated_model.joblib",
            "feature_schema": "models/feature_schema.json",
            "thresholds": "models/threshold.json",
            "feature_definitions": "reports/feature_dictionary.md",
        },
    }
    (models_dir / "model_metadata.json").write_text(json.dumps(meta, indent=2))
    log.info("saved %s", models_dir / "model_metadata.json")


if __name__ == "__main__":
    main()
