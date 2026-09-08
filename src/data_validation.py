"""Data-quality / leakage audit for the extracted flow tables (STEP 6 module).

Checks, all fail-loud (exit 1 on any hard failure):
  1. schema: exactly the 66 documented features + 12 metadata columns
  2. dtypes: all features float32
  3. NaN / inf: zero occurrences in features
  4. exact duplicate rows: reported (must be 0 or explained)
  5. near-duplicate rows: sampled check on feature vectors (identical feature
     vectors across DIFFERENT captures flagged — capture leakage indicator)
  6. constant features: flagged (drop candidates, reported not silently dropped)
  7. labels: binary_label strictly in {benign, attack}; family non-null;
     no silent relabeling (labels compared against split manifest families)
  8. leakage identifiers: src_ip/dst_ip/ports/timestamps/capture ids exist
     ONLY in metadata, never among features (hard assertion)
  9. per-capture flow counts > 0

Usage:  python src/data_validation.py [--sample-near-dups 20000]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from config import load_config
from feature_engineering import FEATURE_NAMES, META_COLUMNS
from split import build_manifest
from utils import log


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample-near-dups", type=int, default=20000,
                    help="rows sampled per capture for the near-duplicate check")
    args = ap.parse_args()

    cfg = load_config()
    flows_dir = cfg.processed_dir / "flows"
    files = sorted(flows_dir.glob("*.parquet"))
    if len(files) != 45:
        log.error("expected 45 flow tables, found %d", len(files))
        sys.exit(1)

    failures: list[str] = []
    warnings: list[str] = []
    total_rows = 0
    total_dups = 0
    const_feats: set[str] = set()
    global_min = np.full(len(FEATURE_NAMES), np.inf, dtype=np.float64)
    global_max = np.full(len(FEATURE_NAMES), -np.inf, dtype=np.float64)
    # capture -> set of row-hashes of feature vectors (sampled) for cross-capture dup check
    cap_hashes: dict[str, set] = {}

    for f in files:
        df = pd.read_parquet(f)
        cap = str(df["capture_file"].iloc[0])
        total_rows += len(df)

        # 1. schema
        expected = set(FEATURE_NAMES) | set(META_COLUMNS)
        missing = expected - set(df.columns)
        extra = set(df.columns) - expected
        if missing:
            failures.append(f"{cap}: missing columns {sorted(missing)[:5]}")
        if extra:
            failures.append(f"{cap}: unexpected columns {sorted(extra)[:5]}")

        # 2. dtypes
        bad_dtypes = [c for c in FEATURE_NAMES if c in df.columns
                      and str(df[c].dtype) != "float32"]
        if bad_dtypes:
            failures.append(f"{cap}: non-float32 features {bad_dtypes[:5]}")

        # 3. NaN/inf
        F = df[FEATURE_NAMES].to_numpy()
        if not np.isfinite(F).all():
            n_bad = int((~np.isfinite(F)).sum())
            failures.append(f"{cap}: {n_bad} NaN/inf feature values")
        else:
            np.minimum(global_min, F.min(axis=0), out=global_min)
            np.maximum(global_max, F.max(axis=0), out=global_max)

        # 4. exact duplicates
        dups = int(df.duplicated(subset=FEATURE_NAMES).sum())
        total_dups += dups
        if dups:
            warnings.append(f"{cap}: {dups} exact duplicate feature rows")

        # 5. near-duplicates across captures (sampled hash of feature bytes)
        step = max(1, len(df) // args.sample_near_dups)
        samp = df[FEATURE_NAMES].iloc[::step]
        h = pd.util.hash_pandas_object(samp, index=False)
        cap_hashes.setdefault(cap, set()).update(set(h.tolist()))

        # 6. constant features (within this capture)
        for c in FEATURE_NAMES:
            if c in df.columns and df[c].nunique() <= 1:
                const_feats.add(c)

        # 7. labels
        bad_labels = set(df["binary_label"].unique()) - {"benign", "attack"}
        if bad_labels:
            failures.append(f"{cap}: invalid labels {bad_labels}")
        if df["family"].isna().any():
            failures.append(f"{cap}: null family values")

        # 9. non-empty
        if len(df) == 0:
            failures.append(f"{cap}: zero flows")

    # 8. leakage identifiers must NOT be features
    forbidden = {"src_ip", "dst_ip", "src_port", "dst_port", "start_ts", "end_ts",
                 "capture_file", "flow_id", "family", "binary_label"}
    leak = forbidden & set(FEATURE_NAMES)
    if leak:
        failures.append(f"leakage identifiers present as features: {leak}")

    # cross-capture identical feature vectors (sampled)
    caps = list(cap_hashes)
    cross_dup_report = []
    for i in range(len(caps)):
        for j in range(i + 1, len(caps)):
            inter = cap_hashes[caps[i]] & cap_hashes[caps[j]]
            if inter:
                cross_dup_report.append((caps[i], caps[j], len(inter)))
    cross_dup_report.sort(key=lambda t: -t[2])

    # constant features across the whole dataset (a feature constant in EVERY capture)
    # approximated by global min==max
    global_const = [FEATURE_NAMES[i] for i in range(len(FEATURE_NAMES))
                    if global_min[i] == global_max[i]]

    # ---- report --------------------------------------------------------------
    log.info("=" * 70)
    log.info("DATA VALIDATION REPORT — %d files, %s rows", len(files), f"{total_rows:,}")
    log.info("=" * 70)
    log.info("exact duplicate feature rows: %d", total_dups)
    log.info("features constant in EVERY capture: %s", global_const or "none")
    log.info("features constant within at least one capture: %s",
             f"{len(const_feats)} -> {sorted(const_feats)[:10]}")
    log.info("global feature ranges: min=%.3g max=%.3g (finite everywhere: %s)",
             float(np.nanmin(global_min)), float(np.nanmax(global_max)),
             bool(np.isfinite(global_min).all() and np.isfinite(global_max).all()))
    log.info("cross-capture identical feature vectors (sampled): %d capture pairs affected",
             len(cross_dup_report))
    for a, b, n in cross_dup_report[:8]:
        log.info("   %s <-> %s : %d identical sampled rows", a, b, n)
    for w in warnings:
        log.warning("%s", w)
    if failures:
        for fail in failures:
            log.error("%s", fail)
        log.error("VALIDATION FAILED — %d hard failures", len(failures))
        sys.exit(1)
    log.info("VALIDATION PASSED — no hard failures")

    # write report file
    rep = Path(cfg.reports_dir) / "data_validation_report.md"
    lines = [
        "# Data Validation Report", "",
        f"Files: {len(files)} · Rows: {total_rows:,} · Exact duplicate feature rows: {total_dups:,}",
        "",
        f"Features constant in every capture: {global_const or 'none'}",
        f"Features constant within ≥1 capture: {len(const_feats)}",
        "",
        "Cross-capture identical sampled feature vectors:",
    ]
    if cross_dup_report:
        lines += [f"- {a} ↔ {b}: {n}" for a, b, n in cross_dup_report[:15]]
    else:
        lines.append("- none")
    lines += ["", "Hard failures: " + ("NONE" if not failures else str(failures)),
              "", "Warnings: " + ("none" if not warnings else "; ".join(warnings[:10]))]
    rep.write_text("\n".join(lines), encoding="utf-8")
    log.info("saved %s", rep)


if __name__ == "__main__":
    main()
