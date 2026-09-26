"""Shared test fixtures.

Dataset-path handling
---------------------
Most tests need a valid ``load_config()``. On the original development machine
the dataset was configured via ``configs/config.yaml``; on fresh clones the
dataset is intentionally absent (the raw PCAPs are never committed).

Two clean cases are supported:

1. ``DDOS_AT_DATASET_PATH`` is set (full local reproduction) -> used as-is.
2. Not set -> tests that only exercise artifacts/tables/inference get a valid
   config pointing at the repository root (dataset discovery tests then
   skip explicitly because no PCAPs exist there).

This keeps ``pytest -q`` green on a fresh clone while preserving every
artifact-based test (model loading, single-record inference, causality,
final-test integrity).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def config_env():
    """Guarantee a loadable config even without a local dataset."""
    if not os.environ.get("DDOS_AT_DATASET_PATH"):
        os.environ["DDOS_AT_DATASET_PATH"] = str(REPO_ROOT)
    yield
