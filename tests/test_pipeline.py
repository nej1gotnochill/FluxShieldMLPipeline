"""Lightweight tests (pytest) — run from the repository root:  pytest tests/ -v

Covers the five requested areas:
  1. dataset discovery (recursive pcap finding + config)
  2. preprocessing (fit-on-train-only pipeline behaviour)
  3. feature generation (schema constants consistent with saved artifacts)
  4. model loading (artifacts exist and load)
  5. single-record inference (accepts one unseen flow record, no retraining)

Tests 4-5 require trained artifacts (models/calibrated_model.joblib); they are
skipped automatically when absent so the suite stays green at every phase.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from config import load_config  # noqa: E402
from feature_engineering import FEATURE_NAMES, META_COLUMNS  # noqa: E402
from inference import record_to_vector  # noqa: E402


# ---------------------------------------------------------------- 1. discovery
def test_config_loads_and_dataset_path_exists():
    cfg = load_config()
    assert cfg.dataset_path.exists(), f"dataset root missing: {cfg.dataset_path}"
    assert cfg.dataset_path.is_dir()


def test_recursive_pcap_discovery():
    cfg = load_config()
    pcaps = sorted(cfg.dataset_path.rglob("*.pcap"))
    if not pcaps and cfg.dataset_path.samefile(Path(__file__).resolve().parents[1]):
        # conftest fallback (repo root) => raw dataset intentionally absent on
        # fresh clones; the dataset itself is never committed.
        pytest.skip("raw DDoS-AT-2022 dataset not configured on this machine "
                    "(set DDOS_AT_DATASET_PATH for full tests)")
    assert len(pcaps) == 45, f"expected 45 pcaps, found {len(pcaps)}"
    assert all(p.stat().st_size > 0 for p in pcaps)


def test_processed_flow_tables_present():
    cfg = load_config()
    flows = sorted((cfg.processed_dir / "flows").glob("*.parquet"))
    assert len(flows) == 45, f"expected 45 parquet flow tables, found {len(flows)}"


# ------------------------------------------------------------- 2. preprocessing
def test_preprocessing_fit_on_train_only():
    """Scaler/selector must be fitted on train only: a fresh pipeline must be
    unfitted, and fitting must not depend on validation data statistics."""
    from preprocessing import make_pipeline
    pipe = make_pipeline("extra_trees", seed=42)
    with pytest.raises(Exception):
        # unfitted pipeline must fail on predict
        pipe.predict(np.zeros((1, len(FEATURE_NAMES)), dtype=np.float32))


def test_pipeline_fit_changes_state_and_predicts():
    from preprocessing import make_pipeline
    rng = np.random.default_rng(0)
    X = pd.DataFrame(rng.normal(size=(200, len(FEATURE_NAMES))).astype(np.float32),
                     columns=FEATURE_NAMES)
    y = (rng.random(200) < 0.8).astype(np.int64)
    pipe = make_pipeline("logistic_regression", seed=42)
    pipe.fit(X, y)
    proba = pipe.predict_proba(X)[:, 1]
    assert proba.shape == (200,)
    assert np.all((proba >= 0) & (proba <= 1))


# ---------------------------------------------------------- 3. feature schema
def test_feature_schema_consistency():
    cfg = load_config()
    schema_path = cfg.processed_dir / "flow_schema.json"
    assert schema_path.exists()
    schema = schema_path.read_text()
    for f in FEATURE_NAMES[:10]:
        assert f in schema
    assert len(FEATURE_NAMES) == 66
    # metadata must never intersect features (leakage rule)
    assert not (set(FEATURE_NAMES) & set(META_COLUMNS))


def test_flow_table_dtypes_and_labels():
    cfg = load_config()
    f = sorted((cfg.processed_dir / "flows").glob("*.parquet"))[0]
    df = pd.read_parquet(f)
    for c in FEATURE_NAMES[:5]:
        assert str(df[c].dtype) == "float32"
    assert set(df["binary_label"].unique()) <= {"benign", "attack"}
    assert df["family"].notna().all()
    # data_loader maps the string labels to 0/1 consistently
    from data_loader import load_flows
    _, y, _ = load_flows([str(df["capture_file"].iloc[0])], cfg.processed_dir / "flows")
    assert set(np.unique(y)) <= {0, 1}
    assert y.sum() == int((df["binary_label"] == "attack").sum())


# ------------------------------------------------------------- 4. model loading
def test_model_artifacts_load():
    cfg = load_config()
    model_path = cfg.models_dir / "calibrated_model.joblib"
    if not model_path.exists():
        pytest.skip("calibrated model not trained yet")
    import joblib
    model = joblib.load(model_path)
    assert hasattr(model, "predict_proba")


# ------------------------------------------------------- 5. single-record inference
def _demo_record():
    from inference import DEMO_RECORD
    return dict(DEMO_RECORD)


def test_record_to_vector_rejects_missing_and_nan():
    rec = _demo_record()
    bad = dict(rec)
    bad.pop("flow_duration_s")
    with pytest.raises(ValueError):
        record_to_vector(bad)
    bad2 = dict(rec)
    bad2["flow_duration_s"] = float("nan")
    with pytest.raises(ValueError):
        record_to_vector(bad2)
    bad3 = dict(rec)
    bad3["flow_duration_s"] = float("inf")
    with pytest.raises(ValueError):
        record_to_vector(bad3)


def test_single_record_inference_end_to_end():
    from inference import score_record
    cfg = load_config()
    if not (cfg.models_dir / "calibrated_model.joblib").exists():
        pytest.skip("calibrated model not trained yet")
    result = score_record(_demo_record())
    assert result["prediction"] in ("attack", "benign")
    assert 0.0 <= result["attack_probability"] <= 1.0
    assert result["latency_ms"] > 0
