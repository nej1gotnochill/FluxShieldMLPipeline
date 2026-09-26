"""Central configuration loading for the Netra DDoS-AT-2022 pipeline.

Priority order for every setting:
    1. Environment variables (DDOS_AT_DATASET_PATH, DDOS_AT_CONFIG)
    2. configs/config.yaml at the repository root
    3. Hard-coded fallbacks

Usage:
    from config import load_config
    cfg = load_config()
    print(cfg.dataset_path, cfg.processed_dir)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

# src/config.py -> repository root
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = REPO_ROOT / "configs" / "config.yaml"


@dataclass(frozen=True)
class Config:
    dataset_path: Path          # raw DDoS-AT-2022 root (read-only)
    data_dir: Path              # processed flow tables (gitignored)
    processed_dir: Path         # alias of data_dir/processed content
    models_dir: Path
    experiments_dir: Path
    reports_dir: Path

    # flow extraction
    flow_timeout_sec: float
    activity_timeout_sec: float
    max_packets_per_flow: int

    # splits
    train_frac: float
    val_frac: float
    test_frac: float
    random_seed: int


def _resolve(base: Path, value: str) -> Path:
    p = Path(os.path.expandvars(str(value)))
    return p if p.is_absolute() else (base / p).resolve()


def load_config(config_path: str | os.PathLike | None = None) -> Config:
    """Load pipeline configuration. Env vars override the YAML file."""
    cfg_file = Path(os.environ.get("DDOS_AT_CONFIG", config_path or DEFAULT_CONFIG_PATH))
    data: dict = {}
    if cfg_file.exists():
        with open(cfg_file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

    ds = data.get("dataset", {})
    paths = data.get("paths", {})
    flow = data.get("flow_extraction", {})
    splits = data.get("splits", {})

    # Env override wins over YAML for the dataset location.
    dataset_raw = os.environ.get("DDOS_AT_DATASET_PATH", ds.get("dataset_path", ""))
    if not dataset_raw:
        raise ValueError(
            "Dataset path not configured: set DDOS_AT_DATASET_PATH or dataset.dataset_path "
            f"in {cfg_file}"
        )

    base = REPO_ROOT
    data_dir = _resolve(base, paths.get("data", "data"))
    return Config(
        dataset_path=Path(dataset_raw).expanduser().resolve(),
        data_dir=data_dir,
        processed_dir=data_dir / "processed",
        models_dir=_resolve(base, paths.get("models", "models")),
        experiments_dir=_resolve(base, paths.get("experiments", "experiments")),
        reports_dir=_resolve(base, paths.get("reports", "reports")),
        flow_timeout_sec=float(flow.get("flow_timeout_sec", 120)),
        activity_timeout_sec=float(flow.get("activity_timeout_sec", 1800)),
        max_packets_per_flow=int(flow.get("max_packets_per_flow", 100000)),
        train_frac=float(splits.get("train", 0.70)),
        val_frac=float(splits.get("val", 0.15)),
        test_frac=float(splits.get("test", 0.15)),
        random_seed=int(splits.get("random_seed", 42)),
    )


if __name__ == "__main__":
    cfg = load_config()
    print("dataset_path    :", cfg.dataset_path)
    print("processed_dir   :", cfg.processed_dir)
    print("models_dir      :", cfg.models_dir)
    print("reports_dir     :", cfg.reports_dir)
    print("flow timeouts   :", cfg.flow_timeout_sec, "/", cfg.activity_timeout_sec, "s")
    print("split fractions :", cfg.train_frac, cfg.val_frac, cfg.test_frac, "seed", cfg.random_seed)
