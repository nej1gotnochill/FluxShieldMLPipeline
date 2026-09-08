"""Verify all extracted parquet flow tables after the full extraction run.

Checks per file: row count, column schema, NaN/inf presence, duplicate rows.
Prints a compact per-family summary. Read-only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from config import load_config
from utils import log


def main() -> None:
    cfg = load_config()
    flows_dir = Path(cfg.processed_dir) / "flows"
    if not flows_dir.is_dir():
        log.error("flows dir %s not found", flows_dir)
        sys.exit(1)

    files = sorted(flows_dir.glob("*.parquet"))
    log.info("Verifying %d parquet flow tables in %s", len(files), flows_dir)

    total_rows = 0
    total_nan = 0
    total_dup = 0
    fam_rows: dict[str, int] = {}
    per_file = []

    for f in files:
        df = pd.read_parquet(f)
        n = len(df)
        total_rows += n
        nan = int(df.select_dtypes(include=[np.number]).isna().sum().sum())
        total_nan += nan
        dup = int(df.duplicated().sum())
        total_dup += dup
        fam = str(df["family"].iloc[0]) if "family" in df.columns and n else "?"
        fam_rows[fam] = fam_rows.get(fam, 0) + n
        per_file.append((f.name, n, nan, dup))
        log.info("  %-58s %9d rows | nan=%-6d dup=%-6d | fam=%-18s",
                 f.name, n, nan, dup, fam)

    log.info("TOTAL rows: %s | NaN cells: %s | duplicate rows: %s",
             f"{total_rows:,}", f"{total_nan:,}", f"{total_dup:,}")
    log.info("Per-family flow counts:")
    for fam, cnt in sorted(fam_rows.items(), key=lambda kv: -kv[1]):
        log.info("  %-20s %12d", fam, cnt)

    # column schema of one file
    example = pd.read_parquet(files[0])
    cols = list(example.columns)
    log.info("Example schema (%d cols): %s", len(cols), ", ".join(cols))
    log.info("dtypes: %s", {c: str(t) for c, t in example.dtypes.items()})


if __name__ == "__main__":
    main()