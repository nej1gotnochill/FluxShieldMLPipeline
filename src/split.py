"""Capture-disjoint split manifest for DDoS-AT-2022.

Design
------
All 45 captures are ordered chronologically by first packet timestamp.

TRACK A (primary, capture-disjoint expanding-window walk-forward):
  * FINAL TEST  = the two LATEST chronological groups (May 4-6, 15 captures)
    PLUS the 2 latest May-3 benign captures -> contiguous two-class block
    (May 3-6, 17 captures). Attack-only latest captures cannot measure FPR;
    composition approved by the user. Never used for feature selection,
    tuning, threshold, calibration or model selection. Touched once.
  * Development = the 28 earlier captures (Mar 17 - May 3), used only for
    walk-forward folds:
        Fold 1: train = captures 0-8   (Mar 17-29)   val = 9-13   (Apr 1)
        Fold 2: train = captures 0-13  (Mar+Apr)     val = 14-21  (May 3 first 8)
        Fold 3: train = captures 0-21  (->May3 8)    val = 22-27  (May 3 next 6)
    Each capture appears in exactly one role per fold; windows expand.

TRACK B (generalization, also capture-disjoint):
  * Held out entirely: tcp_syn_flood (1 capture), tcp_rst (1 capture),
    udp_flood (3 captures - ALL captures of the family).
  * Training: the remaining development captures (25). No held-out capture
    ever appears in training.

Verification performed here:
  * every capture has exactly one role per track
  * no capture appears in two roles of the same track
  * final test is disjoint from all training/validation
  * Track B holdout disjoint from Track B training
  * flows are grouped by capture => capture-disjointness implies row disjointness
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from config import load_config
from utils import log

# Chronological index boundaries over the 45 sorted captures (0-based, exclusive end).
# Derived from measured first-packet times; see reports/flow_validation_report.md.
FINAL_TEST_INDICES = (28, 45)          # May 3 (last 2 benign caps) + May 4-6 (15 attack
                                       # caps): contiguous two-class block, untouched.
                                       # (May 4-6 alone is attack-only -> FPR unmeasurable;
                                       #  user-approved composition, see final-test report.)
TRACK_A_FOLDS = [                      # (train_start, train_end, val_start, val_end)
    (0, 9, 9, 14),                     # fold 1: train Mar 17-29 (9), val Apr 1 (5)
    (0, 14, 14, 22),                   # fold 2: train +Apr (14), val May 3 first 8
    (0, 22, 22, 28),                   # fold 3: train +May3 first8 (22), val May 3 next 6
]
TRACK_B_HOLDOUT_FAMILIES = ("tcp_syn_flood", "tcp_rst", "udp_flood")


@dataclass
class CaptureInfo:
    name: str
    family: str
    first_ts: float
    n_flows: int
    n_packets: int


def capture_inventory(flows_dir: Path) -> list[CaptureInfo]:
    """Per-capture metadata from the parquet flow tables (cheap column reads)."""
    out = []
    for f in sorted(flows_dir.glob("*.parquet")):
        df = pd.read_parquet(f, columns=["capture_file", "family", "start_ts", "n_packets"])
        out.append(CaptureInfo(
            name=str(df["capture_file"].iloc[0]),
            family=str(df["family"].iloc[0]),
            first_ts=float(df["start_ts"].min()),
            n_flows=int(len(df)),
            n_packets=int(df["n_packets"].sum()),
        ))
    out.sort(key=lambda c: c.first_ts)
    return out


def build_manifest(cfg) -> pd.DataFrame:
    caps = capture_inventory(cfg.processed_dir / "flows")
    if len(caps) != 45:
        log.error("expected 45 captures, found %d", len(caps))
        sys.exit(1)

    rows = []
    for i, c in enumerate(caps):
        # ---- Track A role -------------------------------------------------
        if FINAL_TEST_INDICES[0] <= i < FINAL_TEST_INDICES[1]:
            track_a_role = "final_test"
            fold = -1
        else:
            track_a_role = "train"
            fold = None
            for fi, (ts, te, vs, ve) in enumerate(TRACK_A_FOLDS):
                if vs <= i < ve:
                    track_a_role = "val"
                    fold = fi + 1
                elif ts <= i < te:
                    fold = fi + 1  # belongs to this fold's training window
        # ---- Track B role -------------------------------------------------
        track_b_role = "holdout" if c.family in TRACK_B_HOLDOUT_FAMILIES else "train"
        if track_a_role == "final_test":
            track_b_role = "final_test"  # final test is untouched for BOTH tracks

        rows.append({
            "capture": c.name,
            "family": c.family,
            "first_ts": c.first_ts,
            "date": pd.Timestamp(c.first_ts, unit="s", tz="UTC").strftime("%Y-%m-%d"),
            "n_flows": c.n_flows,
            "n_packets": c.n_packets,
            "track_a_role": track_a_role,
            "track_a_fold": fold if fold is not None else "",
            "track_b_role": track_b_role,
        })

    m = pd.DataFrame(rows)
    m["date_time"] = pd.to_datetime(m["first_ts"], unit="s", utc=True)
    return m


def verify_manifest(m: pd.DataFrame) -> bool:
    ok = True
    n = len(m)

    # 1. exactly one role per track
    if m["track_a_role"].isna().any() or m["track_b_role"].isna().any():
        log.error("capture with missing role")
        ok = False
    if m["track_a_role"].nunique() < 3 or m["track_b_role"].nunique() < 2:
        log.error("role cardinality wrong: A=%s B=%s",
                  m["track_a_role"].unique(), m["track_b_role"].unique())
        ok = False

    # 2. no capture in two roles of the same track (roles are single-valued by construction,
    #    verify via fold windows)
    for _, r in m.iterrows():
        if r["track_a_role"] == "val" and r["track_a_fold"] == "":
            log.error("val capture without fold: %s", r["capture"])
            ok = False

    # 3. final test disjoint from train/val
    dev = set(m.loc[m["track_a_role"] != "final_test", "capture"])
    fin = set(m.loc[m["track_a_role"] == "final_test", "capture"])
    if dev & fin:
        log.error("final test overlaps development: %s", dev & fin)
        ok = False

    # 4. Track B holdout disjoint from Track B training
    hold = set(m.loc[m["track_b_role"] == "holdout", "capture"])
    btrain = set(m.loc[m["track_b_role"] == "train", "capture"])
    if hold & btrain:
        log.error("Track B holdout overlaps training: %s", hold & btrain)
        ok = False
    if hold & fin:
        log.error("Track B holdout overlaps final test: %s", hold & fin)
        ok = False

    # 5. within each fold: train and val disjoint, both inside development.
    #    Across folds: validation sets pairwise disjoint (training windows may
    #    overlap - that is the expanding-window design).
    val_sets = []
    for (ts, te, vs, ve) in TRACK_A_FOLDS:
        tr = set(range(ts, te))
        va = set(range(vs, ve))
        if tr & va:
            log.error("fold train/val overlap")
            ok = False
        if max(ts, te, vs, ve) > FINAL_TEST_INDICES[0]:
            log.error("fold window reaches into final test")
            ok = False
        if te > vs:
            log.error("fold train window extends past its validation start")
            ok = False
        val_sets.append(va)
    for i in range(len(val_sets)):
        for j in range(i + 1, len(val_sets)):
            if val_sets[i] & val_sets[j]:
                log.error("validation sets overlap across folds")
                ok = False

    # 6. flow disjointness: rows are keyed by capture; capture disjointness => row disjointness.
    #    Double-check no capture name appears twice.
    if m["capture"].duplicated().any():
        log.error("duplicate capture names in manifest")
        ok = False

    log.info("verification: %s", "PASS - every capture has exactly one role per track, "
             "no overlap, final test untouched" if ok else "FAIL")
    return ok


def main() -> None:
    cfg = load_config()
    m = build_manifest(cfg)
    ok = verify_manifest(m)
    if not ok:
        log.error("split manifest verification FAILED - refusing to continue")
        sys.exit(1)

    out_csv = Path(cfg.reports_dir) / "split_manifest.csv"
    out_json = Path(cfg.reports_dir) / "split_manifest.json"
    m.drop(columns=["date_time"]).to_csv(out_csv, index=False)
    out_json.write_text(m.to_json(orient="records", indent=2), encoding="utf-8")

    # printable manifest
    log.info("split manifest written to %s", out_csv)
    for _, r in m.iterrows():
        log.info("  %-52s %-12s %-10s A=%-9s %-2s B=%s",
                 r["capture"], r["date"], r["family"],
                 r["track_a_role"], r["track_a_fold"], r["track_b_role"])

    # per-role flow counts
    log.info("Track A flow counts:")
    for role in ["train", "val", "final_test"]:
        sub = m[m["track_a_role"] == role]
        log.info("  %-10s %2d captures  %9d flows  %s",
                 role, len(sub), int(sub["n_flows"].sum()),
                 ", ".join(sub["family"].value_counts().index.tolist()))
    log.info("Track B flow counts:")
    for role in ["train", "holdout", "final_test"]:
        sub = m[m["track_b_role"] == role]
        log.info("  %-10s %2d captures  %9d flows  %s",
                 role, len(sub), int(sub["n_flows"].sum()),
                 ", ".join(f"{k}×{v}" for k, v in sub["family"].value_counts().items()))


if __name__ == "__main__":
    main()