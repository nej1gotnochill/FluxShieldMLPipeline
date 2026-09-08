"""Shared helpers for the four research-strengthening analyses.

All analyses are DEVELOPMENT-ONLY and use the FROZEN artifacts. Nothing here
writes to models/, experiments/final_test_results.csv, or any official report.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from config import load_config  # noqa: E402
from data_loader import load_flows  # noqa: E402
from feature_engineering import FEATURE_NAMES  # noqa: E402
from split import TRACK_B_HOLDOUT_FAMILIES, build_manifest, verify_manifest  # noqa: E402
from train import make_group_folds  # noqa: E402

RESEARCH_DIR = Path("experiments/research")

# Feature groups derived from the ACTUAL schema (reports/feature_dictionary.md,
# FEATURE_NAMES above). Groups are non-exclusive; overlap is documented in the
# ablation report rather than hidden.
FEATURE_GROUPS: dict[str, list[str]] = {
    "B_rate_statistical": [
        "flow_bytes_s", "flow_packets_s", "avg_pkt_size", "avg_fwd_seg",
        "avg_bwd_seg", "down_up_ratio", "pkt_len_max", "pkt_len_min",
        "pkt_len_mean", "pkt_len_std", "flow_duration_s",
    ],
    "C_directional": [
        "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
        "fwd_len_max", "fwd_len_min", "fwd_len_mean", "fwd_len_std",
        "bwd_len_max", "bwd_len_min", "bwd_len_mean", "bwd_len_std",
        "fwd_header_bytes", "bwd_header_bytes", "fwd_data_pkts",
        "bwd_data_pkts",
    ],
    "D_timing_iat": [
        "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
        "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max",
        "fwd_iat_min", "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std",
        "bwd_iat_max", "bwd_iat_min",
        # causal-active/idle (in-window closed periods; documented in the
        # feature dictionary's early-window rule)
        "active_mean", "active_std", "active_max", "active_min",
        "idle_mean", "idle_std", "idle_max", "idle_min",
    ],
    "E_tcp_behavior": [
        "fin_count", "syn_count", "rst_count", "psh_count", "ack_count",
        "urg_count", "ece_count", "cwr_count", "fwd_psh", "bwd_psh",
        "fwd_urg", "bwd_urg", "init_fwd_win", "init_bwd_win",
        "fwd_win_mean", "bwd_win_mean",
    ],
    "F_protocol_indicator": ["protocol"],
}

# 5 globally-constant features flagged by data_validation (documented drop
# candidates). Included in "all 66" for fidelity; their contribution is
# measured by the protocol/indicator group.
CONSTANT_FEATURES = ["fwd_urg", "bwd_urg", "urg_count", "ece_count", "cwr_count"]


def frozen_model():
    import joblib
    cfg = load_config()
    return joblib.load(cfg.models_dir / "calibrated_model.joblib")


def frozen_threshold() -> float:
    cfg = load_config()
    th = json.loads((cfg.models_dir / "threshold.json").read_text())
    return float(th["thresholds"].get("t_op", 0.5))


def dev_data(extra_cols: list[str] | None = None):
    """Load the 28 development captures (final test NEVER loaded here)."""
    cfg = load_config()
    m = build_manifest(cfg)
    if not verify_manifest(m):
        sys.exit(1)
    dev_caps = m[m["track_a_role"] != "final_test"]["capture"].tolist()
    cols = None if extra_cols is None else list(FEATURE_NAMES) + list(extra_cols)
    X, y, meta = load_flows(dev_caps, cfg.processed_dir / "flows", extra_cols=cols)
    return X, y, meta, m


def a2_folds(dev_caps, groups, y):
    cfg = load_config()
    folds, used_seed = make_group_folds(dev_caps, groups, y, n_splits=5,
                                        seed0=cfg.random_seed)
    return folds, used_seed


def track_b_split(meta: pd.DataFrame):
    """Track B family-holdout split (dev captures only).

    Returns (train_idx, holdout_idx) positional arrays. NOTE: the official
    Track B holdout families are tcp_syn_flood, tcp_rst, udp_flood; udp_flood
    captures may lie in the final-test block (final_test role) — the holdout
    covers every dev capture of those families so no held-out family capture
    is ever trained on.
    """
    from split import FINAL_TEST_INDICES  # noqa: F401  (documented boundary)
    b_hold = meta["family"].isin(TRACK_B_HOLDOUT_FAMILIES)
    hold_idx = np.where(b_hold.to_numpy())[0]
    tr_idx = np.where((~b_hold).to_numpy())[0]
    return tr_idx, hold_idx


def evaluate_at_threshold(y_true, proba, t: float) -> dict:
    """Metrics at a fixed threshold, reusing the project's evaluate_binary."""
    from evaluate import evaluate_binary
    pred = (proba >= t).astype(np.int64)
    return evaluate_binary(y_true, pred, proba)


def drop_duplicates_dev(X: pd.DataFrame, y: np.ndarray, meta: pd.DataFrame):
    """Remove exact duplicate FEATURE rows (keep-first), documented order."""
    dups = X.duplicated(subset=list(FEATURE_NAMES), keep="first")
    keep_mask = ~dups.to_numpy()
    n_dup = int(dups.sum())
    X_d = X.loc[keep_mask].reset_index(drop=True)
    meta_d = meta.loc[keep_mask].reset_index(drop=True)
    y_d = y[keep_mask]
    return X_d, y_d, meta_d, n_dup


def json_dump(obj, path: Path) -> None:
    path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")
    print(f"saved {path}")
