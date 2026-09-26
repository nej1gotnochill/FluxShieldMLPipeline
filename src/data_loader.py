"""Flow-table loading for training/evaluation.

Reads per-capture parquet flow tables (float32) and returns only the requested
columns. Never loads the raw dataset; loads one capture at a time and
concatenates staged (bounded number of frames).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from feature_engineering import FEATURE_NAMES

# Columns that are metadata (never features) but needed for grouping/labels.
META_NEEDED = ["capture_file", "family", "binary_label", "flow_id"]


def load_flows(
    capture_names: list[str],
    flows_dir: Path,
    feature_cols: list[str] | None = None,
    extra_cols: list[str] | None = None,
) -> tuple[pd.DataFrame, np.ndarray, pd.DataFrame]:
    """Load flow rows for the given captures.

    Returns (X, y, meta):
      X    : float32 DataFrame of feature columns
      y    : int64 array, 1 = attack, 0 = benign
      meta : DataFrame(capture_file, family, binary_label, flow_id)
    """
    feature_cols = feature_cols or list(FEATURE_NAMES)
    extra_cols = extra_cols or META_NEEDED
    wanted = set(feature_cols) | set(extra_cols)
    cap_set = set(capture_names)

    frames = []
    for f in sorted(flows_dir.glob("*.parquet")):
        df = pd.read_parquet(f, columns=sorted(wanted))
        df = df[df["capture_file"].isin(cap_set)]
        if len(df):
            frames.append(df)
    if not frames:
        raise ValueError(f"no flows found for captures: {capture_names}")

    df = pd.concat(frames, ignore_index=True, copy=False)
    del frames

    # fail loudly if any capture is missing entirely
    found = set(df["capture_file"].unique())
    missing = cap_set - found
    if missing:
        raise ValueError(f"captures produced no flows: {sorted(missing)}")

    y = (df["binary_label"].astype(str).str.lower() != "benign").astype(np.int64).to_numpy()
    meta = df[extra_cols].copy()
    X = df[feature_cols].astype(np.float32)
    return X, y, meta


def load_capture_meta(flows_dir: Path) -> pd.DataFrame:
    """Per-capture metadata table (capture_file, family, n_flows)."""
    rows = []
    for f in sorted(flows_dir.glob("*.parquet")):
        df = pd.read_parquet(f, columns=["capture_file", "family"])
        rows.append({"capture_file": str(df["capture_file"].iloc[0]),
                     "family": str(df["family"].iloc[0]),
                     "n_flows": int(len(df))})
    return pd.DataFrame(rows)