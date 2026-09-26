"""Model pipelines for baseline training.

All preprocessing is fitted ONLY on training data inside the sklearn Pipeline,
so inference applies exactly the same transformations. No scaler/selector is
ever fitted on validation or test data.

Baseline set (no tuning yet):
  * logistic_regression : StandardScaler + LogisticRegression (class_weight=balanced)
  * random_forest       : RandomForestClassifier (class_weight=balanced)
  * extra_trees         : ExtraTreesClassifier (class_weight=balanced)
  * hist_gradient_boost : HistGradientBoostingClassifier (no class_weight;
                          caller passes sample_weight computed on train only)
"""
from __future__ import annotations

from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

MODELS = ("logistic_regression", "random_forest", "extra_trees", "hist_gradient_boost")


def make_pipeline(model_name: str, seed: int = 42) -> Pipeline:
    if model_name == "logistic_regression":
        return Pipeline([
            ("scale", StandardScaler()),
            ("model", LogisticRegression(class_weight="balanced", C=1.0,
                                         max_iter=2000, n_jobs=-1, random_state=seed)),
        ])
    if model_name == "random_forest":
        return Pipeline([
            ("model", RandomForestClassifier(n_estimators=100, class_weight="balanced",
                                             n_jobs=-1, random_state=seed)),
        ])
    if model_name == "extra_trees":
        return Pipeline([
            ("model", ExtraTreesClassifier(n_estimators=100, class_weight="balanced",
                                           n_jobs=-1, random_state=seed)),
        ])
    if model_name == "hist_gradient_boost":
        return Pipeline([
            ("model", HistGradientBoostingClassifier(max_iter=200, random_state=seed)),
        ])
    raise ValueError(f"unknown model: {model_name}")


def sample_weights(y: "np.ndarray") -> "np.ndarray":
    """Balanced sample weights from training labels (train-only usage)."""
    import numpy as np
    n = len(y)
    n_pos = int(y.sum())
    n_neg = n - n_pos
    w = np.empty(n, dtype=np.float64)
    w[y == 1] = n / (2.0 * n_pos)
    w[y == 0] = n / (2.0 * n_neg)
    return w