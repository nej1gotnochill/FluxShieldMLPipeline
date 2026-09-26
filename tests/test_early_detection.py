"""Tests for the causal early-window extraction (src/early_detection.py).

Validates the properties the methodology requires:
  1. causality - no packet with t > flow_start + W influences a W-row:
                 (a) structural: no window row's span exceeds W;
                 (b) empirical: rows from the full capture are identical to
                 rows from a capture physically truncated right after the
                 last window boundary (raw-pcap boundary audit).
  2. nesting   - the set of 1s flow rows contains the 3s set contains the 5s
                 set (flows alive at a smaller window remain alive at larger).
  3. frozen artifacts - the scored pipeline is the deployed one
                 (model_metadata.json params == calibrated_model.joblib).
  4. final-test metrics untouched - experiments/final_test_results.csv keeps
                 the STEP 12 values.

Uses one small real capture (httperf_2nd.pcap, benign, 256k packets) so the
suite stays fast; the boundary audit physically truncates a copy under
data/processed/_causality_probe/ (gitignored, deleted after the test).
"""
from __future__ import annotations

import json
import struct
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from config import load_config
from early_detection import extract_window_rows
from feature_engineering import FEATURE_NAMES
from inspect_dataset import discover_files

CAPTURE = "httperf_2nd.pcap"
WINDOWS = [1.0, 3.0, 5.0]


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture(scope="module")
def window_rows(cfg):
    matches = [e for e in discover_files(cfg.dataset_path)
               if e["filename"] == CAPTURE]
    if not matches:
        pytest.skip("raw DDoS-AT-2022 dataset not configured on this machine "
                    "(set DDOS_AT_DATASET_PATH for full tests)")
    e = matches[0]
    job = {"path": e["path"], "family": e["family"],
           "binary_label": e["binary_label"], "windows": WINDOWS,
           "flow_timeout_sec": cfg.flow_timeout_sec,
           "activity_timeout_sec": cfg.activity_timeout_sec,
           "max_packets_per_flow": cfg.max_packets_per_flow}
    return extract_window_rows(job)["rows"]


# ---------------------------------------------------------------- 1. causality
def test_no_window_row_exceeds_boundary(window_rows):
    for wi, W in enumerate(WINDOWS):
        dur = np.asarray(window_rows[wi]["flow_duration_s"])
        assert int((dur > W + 1e-6).sum()) == 0, \
            f"{int((dur > W + 1e-6).sum())} rows exceed the {W}s boundary"


def test_boundary_audit_full_vs_truncated_pcap(cfg, window_rows):
    """Empirical causality: truncate the pcap after the last boundary packet
    and verify every 1s row is IDENTICAL to the full-capture extraction."""
    e = next(e for e in discover_files(cfg.dataset_path)
             if e["filename"] == CAPTURE)
    W = WINDOWS[0]

    # find the last packet timestamp needed by any 1s row: max over rows of
    # (flow start + W) is bounded by (max flow start in 1s rows) + W
    starts = np.asarray(window_rows[0]["start_ts"])
    cut_ts = float(starts.max()) + W

    # physically copy records with ts <= cut_ts into a probe pcap
    probe_dir = cfg.processed_dir / "_causality_probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe = probe_dir / CAPTURE
    try:
        with open(e["path"], "rb") as f:
            ghdr = f.read(24)
            assert ghdr[:4] == b"\xd4\xc3\xb2\xa1"
            rec = struct.Struct("<IIII")
            with open(probe, "wb") as out:
                out.write(ghdr)
                kept = 0
                while True:
                    rh = f.read(16)
                    if len(rh) < 16:
                        break
                    ts_s, ts_f, incl, orig = rec.unpack(rh)
                    data = f.read(incl)
                    ts = ts_s + ts_f / 1e6
                    if ts <= cut_ts:
                        out.write(rh)
                        out.write(data)
                        kept += 1
        assert kept > 0

        e2 = dict(e)
        e2["path"] = str(probe)
        job = {"path": str(probe), "family": e["family"],
               "binary_label": e["binary_label"], "windows": [W],
               "flow_timeout_sec": cfg.flow_timeout_sec,
               "activity_timeout_sec": cfg.activity_timeout_sec,
               "max_packets_per_flow": cfg.max_packets_per_flow}
        trunc_rows = extract_window_rows(job)["rows"][0]

        # every truncated-capture row must equal its full-capture twin
        full = window_rows[0]
        tidx = {fid: i for i, fid in enumerate(trunc_rows["flow_id"])}
        matched = 0
        for i, fid in enumerate(full["flow_id"]):
            j = tidx.get(fid)
            if j is None:
                continue  # flow began after the cut -> not in probe, fine
            matched += 1
            for feat in FEATURE_NAMES:
                a = full[feat][i]
                b = trunc_rows[feat][j]
                if np.isnan(a) or np.isnan(b):
                    assert np.isnan(a) and np.isnan(b)
                else:
                    assert a == b, f"{feat} differs for {fid}: {a} vs {b}"
        assert matched > 1000  # the probe must cover the bulk of flows
    finally:
        probe.unlink(missing_ok=True)
        probe_dir.rmdir()


# ------------------------------------------------------------------ 2. nesting
def test_window_nesting(window_rows):
    ids = [set(window_rows[wi]["flow_id"]) for wi in range(len(WINDOWS))]
    # every 3s row's flow id must exist at 1s (flows alive at 3s were alive at 1s)
    assert ids[0] >= ids[1] >= ids[2], "window row sets are not nested"


def test_no_phantom_rows(window_rows):
    for wi in range(len(WINDOWS)):
        n = np.asarray(window_rows[wi]["n_packets"])
        assert int((n == 0).sum()) == 0, "row with zero packets (phantom flow)"


# -------------------------------------------------------- 3. frozen artifacts
def test_scored_model_is_the_frozen_one(cfg):
    import joblib
    model = joblib.load(cfg.models_dir / "calibrated_model.joblib")
    md = json.loads((cfg.models_dir / "model_metadata.json").read_text())
    et = model.named_steps.get("model") if hasattr(model, "named_steps") else model
    inner = getattr(et, "base_estimator", None) or getattr(et, "estimator", et)
    if hasattr(inner, "named_steps"):  # CalibratedClassifierCV wraps a Pipeline
        inner = inner.named_steps.get("model", inner)
    assert inner.__class__.__name__ == "ExtraTreesClassifier"
    assert inner.n_estimators == md["model"]["params"]["n_estimators"] == 300
    assert inner.max_depth == md["model"]["params"]["max_depth"] == 20
    assert inner.class_weight == md["model"]["params"]["class_weight"] == "balanced"
    th = json.loads((cfg.models_dir / "threshold.json").read_text())
    assert th["calibrator"] == "sigmoid"
    assert th["thresholds"]["t_op"] == 0.5


# ----------------------------------------------- 4. final-test metrics intact
def test_final_test_metrics_unchanged(cfg):
    ft = pd.read_csv(cfg.experiments_dir / "final_test_results.csv").iloc[0]
    assert ft["n_benign"] + ft["n_attack"] == 448_076
    assert ft["n_attack"] == 442_521
    assert ft["n_benign"] == 5_555
    assert round(ft["recall"], 4) == 0.9978
    assert round(ft["fpr"], 5) == 0.00018
    assert ft["threshold"] == 0.5
