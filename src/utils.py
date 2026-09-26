"""Shared pipeline utilities: staged progress logging, timing, memory reporting."""
from __future__ import annotations

import logging
import random
import sys
import time
from contextlib import contextmanager

import numpy as np

try:
    import psutil
    _PSUTIL = True
except ImportError:  # pragma: no cover
    _PSUTIL = False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("fluxshield")


def rss_mb() -> float:
    """Current process resident memory in MB (0 if psutil unavailable)."""
    if not _PSUTIL:
        return 0.0
    return psutil.Process().memory_info().rss / (1 << 20)


def log_stage(step: int, total: int, name: str) -> None:
    log.info("[%d/%d] %s", step, total, name)


@contextmanager
def timed_stage(step: int, total: int, name: str, memory: bool = True):
    """Stage wrapper: logs start, elapsed time and memory delta at exit."""
    log_stage(step, total, name)
    mem0 = rss_mb() if memory else 0.0
    t0 = time.perf_counter()
    yield
    dt = time.perf_counter() - t0
    if memory and _PSUTIL:
        mem1 = rss_mb()
        log.info("[%d/%d] %s done in %.1fs (RSS %.0f -> %.0f MB, peak tracked separately)",
                 step, total, name, dt, mem0, mem1)
    else:
        log.info("[%d/%d] %s done in %.1fs", step, total, name, dt)


def set_seeds(seed: int = 42) -> None:
    """Deterministic seeds for python/numpy (sklearn models get seed= via params)."""
    random.seed(seed)
    np.random.seed(seed)
