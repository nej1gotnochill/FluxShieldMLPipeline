"""Evaluation metrics for baseline results.

Positive class = attack (1). Reports precision/recall/F1/PR-AUC/ROC-AUC/FPR/FNR
and confusion matrix, plus per-attack-family recall and measured inference
latency/throughput.
"""
from __future__ import annotations

import time

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def evaluate_binary(y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> dict:
    """Metrics with attack as the positive class."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    pr_auc = float(average_precision_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else float("nan")
    roc = float(roc_auc_score(y_true, y_proba)) if len(np.unique(y_true)) > 1 else float("nan")
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "pr_auc": pr_auc,
        "roc_auc": roc,
        "fpr": float(fp / (fp + tn)) if (fp + tn) else float("nan"),
        "fnr": float(fn / (fn + tp)) if (fn + tp) else float("nan"),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "n_benign": int(tn + fp), "n_attack": int(fn + tp),
    }


def per_family_metrics(meta: pd.DataFrame, y_true: np.ndarray, y_pred: np.ndarray,
                       y_proba: np.ndarray) -> pd.DataFrame:
    """Per-family: flow count, recall (family flows flagged attack), mean proba.

    Uses positional indexing (np.where) so it never depends on the caller's
    DataFrame index being reset.
    """
    fam_vals = meta["family"].to_numpy()
    rows = []
    for fam in np.unique(fam_vals):
        i = np.where(fam_vals == fam)[0]
        rows.append({
            "family": str(fam),
            "n_flows": int(len(i)),
            "recall": float(np.mean(y_pred[i] == 1)),
            "mean_proba": float(np.mean(y_proba[i])),
        })
    return pd.DataFrame(rows)


def measure_inference(model, X: np.ndarray, n_single: int = 200, seed: int = 0) -> dict:
    """Measured inference latency/throughput on already-fitted model.

    Throughput: batch predict_proba over the full passed matrix (flows/s).
    Latency: median/mean of n_single single-row predict_proba calls (ms).
    """
    rng = np.random.default_rng(seed)
    # batch throughput
    t0 = time.perf_counter()
    _ = model.predict_proba(X)
    batch_s = time.perf_counter() - t0
    throughput = len(X) / max(batch_s, 1e-9)

    # single-row latency
    idx = rng.integers(0, len(X), size=min(n_single, len(X)))
    lat = []
    for i in idx:
        t0 = time.perf_counter()
        _ = model.predict_proba(X[i:i + 1])
        lat.append((time.perf_counter() - t0) * 1e3)
    lat = np.array(lat)
    return {
        "throughput_flows_s": float(throughput),
        "latency_median_ms": float(np.median(lat)),
        "latency_mean_ms": float(np.mean(lat)),
        "latency_p95_ms": float(np.percentile(lat, 95)),
    }