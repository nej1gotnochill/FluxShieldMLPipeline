"""ANALYSIS 3 — Structured error analysis (evaluation reads only).

The FROZEN model scores existing flow tables; nothing is refitted, no
threshold changes, no official artifact is modified. Outputs go to
experiments/research/ and reports/error_analysis_results.json.

Parts:
  E1. Final-test per-flow scoring -> false negatives / false positives,
      aggregated per family, verified against the OFFICIAL final-test metrics
      (consistency check; the official CSV is NOT rewritten).
  E2. Feature-evidence profiling: for each family's FNs, medians of the
      operationally meaningful features (observation time, packet/byte rates,
      TCP handshake evidence) vs correctly-detected flows of the same family.
  E3. Early-window (1s) deep-dive on the slow-rate families named by the
      user: http_slow_header, http_slow_body, flash_traffic. Causal 1s rows
      are re-extracted with src/early_detection.py's validated extractor and
      scored with the frozen pipeline; FN feature profiles show WHY 1s fails
      (insufficient observation time / no pacing evidence yet).
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from config import load_config  # noqa: E402
from data_loader import load_flows  # noqa: E402
from evaluate import evaluate_binary, per_family_metrics  # noqa: E402
from feature_engineering import FEATURE_NAMES  # noqa: E402
from research_utils import (  # noqa: E402
    RESEARCH_DIR, frozen_model, frozen_threshold, json_dump,
)
from utils import log, set_seeds, timed_stage  # noqa: E402

EVIDENCE_FEATURES = [
    "flow_duration_s", "n_packets_eff", "flow_packets_s", "flow_bytes_s",
    "fwd_packets", "bwd_packets", "syn_count", "ack_count", "rst_count",
    "psh_count", "flow_iat_mean", "fwd_iat_mean", "bwd_iat_mean",
    "fwd_header_bytes", "bwd_header_bytes", "avg_pkt_size", "mean_proba",
]


def main() -> None:
    set_seeds(42)
    t0 = time.perf_counter()
    cfg = load_config()
    model = frozen_model()
    t_op = frozen_threshold()

    md = json.loads((cfg.models_dir / "model_metadata.json").read_text())
    test_caps = md["splits"]["track_a_final_test_captures"]

    # ---------------- E1: final-test per-flow scoring ------------------------
    with timed_stage(1, 4, "E1: scoring final-test flow table (evaluation read)"):
        X, y, meta = load_flows(
            test_caps, cfg.processed_dir / "flows",
            extra_cols=list(FEATURE_NAMES) + ["capture_file", "family",
                                              "binary_label", "flow_id", "n_packets"])
        # n_packets is metadata; keep a copy as evidence feature
        Xe = X.copy()
        Xe["n_packets_eff"] = meta["n_packets"].to_numpy()
        proba = model.predict_proba(X)[:, 1]
        pred = (proba >= t_op).astype(np.int64)
        official = pd.read_csv("experiments/final_test_results.csv").iloc[0]
        m = evaluate_binary(y, pred, proba)
        consistent = all(
            abs(m[k] - float(official[k])) < 5e-4
            for k in ("precision", "recall", "f1", "fpr", "fnr"))
        log.info("consistency vs official final_test_results.csv: %s "
                 "(re-derived R=%.6f vs official %.6f)", consistent,
                 m["recall"], float(official["recall"]))
        if not consistent:
            log.error("RE-DERIVED METRICS DIVERGE FROM OFFICIAL - aborting report")
            sys.exit(1)

        fn_mask = (y == 1) & (pred == 0)
        fp_mask = (y == 0) & (pred == 1)
        log.info("FN=%d FP=%d (of %d attacks / %d benign)",
                 int(fn_mask.sum()), int(fp_mask.sum()),
                 int((y == 1).sum()), int((y == 0).sum()))

        # representative examples (all FPs; up to 25 FNs per family)
        ev_cols = [c for c in EVIDENCE_FEATURES if c != "mean_proba"]
        sc = Xe[ev_cols].copy()
        sc["flow_id"] = meta["flow_id"].to_numpy()
        sc["capture_file"] = meta["capture_file"].to_numpy()
        sc["family"] = meta["family"].to_numpy()
        sc["proba"] = proba
        sc["error"] = np.where(fn_mask, "FN", np.where(fp_mask, "FP", ""))

        fns = sc[fn_mask].copy()
        fps = sc[fp_mask].copy()
        rep = (fns.groupby("family", group_keys=False)
               .apply(lambda g: g.nsmallest(25, "proba"), include_groups=True))
        rep.to_csv(RESEARCH_DIR / "error_examples.csv", index=False)
        fps.to_csv(RESEARCH_DIR / "false_positives_all.csv", index=False)

        # per-family FN evidence vs detected peers
        fam_rows = []
        for fam in np.unique(meta["family"][y == 1]):
            fm = (meta["family"].to_numpy() == fam) & (y == 1)
            det = fm & ~fn_mask
            row = {"family": fam, "n_flows": int(fm.sum()),
                   "n_fn": int((fm & fn_mask).sum()),
                   "fn_rate": float((fm & fn_mask).sum() / max(fm.sum(), 1))}
            for f in [c for c in EVIDENCE_FEATURES if c != "mean_proba"]:
                row[f"{f}_fn_median"] = float(np.median(Xe[f].to_numpy()[fm & fn_mask])) \
                    if (fm & fn_mask).any() else None
                row[f"{f}_det_median"] = float(np.median(Xe[f].to_numpy()[det]))
            fam_rows.append(row)
        fam_df = pd.DataFrame(fam_rows)
        fam_df.to_csv(RESEARCH_DIR / "error_family_evidence.csv", index=False)

    # ---------------- E2: FP profile ----------------------------------------
    with timed_stage(2, 4, "E2: false-positive profile"):
        fp_profile = {}
        if len(fps):
            fp_profile = {
                "n_fp": int(len(fps)),
                "by_capture": fps["capture_file"].value_counts().to_dict(),
                "feature_medians": {c: float(fps[c].median()) for c in ev_cols},
                "proba_range": [float(fps["proba"].min()), float(fps["proba"].max())],
                "benign_feature_medians_for_comparison": {
                    c: float(Xe[c].to_numpy()[y == 0].mean()) for c in
                    ["flow_duration_s", "flow_packets_s", "flow_bytes_s"]},
            }

    # ---------------- E3: 1s deep-dive on slow-rate families -----------------
    with timed_stage(3, 4, "E3: causal 1s re-extraction for slow-rate families"):
        from early_detection import extract_window_rows
        from inspect_dataset import discover_files

        targets = ["slow header", "slowbody", "flash traffic", "http low rate"]
        entries = {Path(e["filename"]).name: e
                   for e in discover_files(cfg.dataset_path)}
        sel_caps = [c for c in test_caps if any(s in c.lower() for s in targets)]
        log.info("1s deep-dive captures: %s", sel_caps)

        rows = {n: [] for n in FEATURE_NAMES} | {c: [] for c in
                                                 ("capture_file", "flow_id", "family", "binary_label")}
        for c in sel_caps:
            job = {"path": entries[c]["path"], "family": entries[c]["family"],
                   "binary_label": entries[c]["binary_label"], "windows": [1.0],
                   "flow_timeout_sec": cfg.flow_timeout_sec,
                   "activity_timeout_sec": cfg.activity_timeout_sec,
                   "max_packets_per_flow": cfg.max_packets_per_flow}
            st = extract_window_rows(job)
            if st.get("error"):
                log.error("extraction error in %s: %s", c, st["error"])
                sys.exit(1)
            b = st["rows"][0]
            for n in FEATURE_NAMES:
                rows[n].extend(b[n])
            for cmeta in ("capture_file", "flow_id", "family", "binary_label"):
                rows[cmeta].extend(b[cmeta])
            log.info("  %-44s %9s pkts -> %6d 1s rows",
                     c, f"{st['packets']:,}", len(b["flow_id"]))

        X1 = pd.DataFrame({n: np.asarray(rows[n], dtype=np.float32)
                           for n in FEATURE_NAMES})
        # evidence column kept OUT of the scoring matrix (fit-time schema = 66)
        n_pkt_eff = (X1["fwd_packets"] + X1["bwd_packets"]).to_numpy()
        y1 = (pd.Series(rows["binary_label"]).astype(str).str.lower()
              != "benign").astype(np.int64).to_numpy()
        meta1 = pd.DataFrame({c: rows[c] for c in
                              ("capture_file", "flow_id", "family", "binary_label")})
        proba1 = model.predict_proba(X1)[:, 1]
        pred1 = (proba1 >= t_op).astype(np.int64)
        m1 = evaluate_binary(y1, pred1, proba1)
        fam1 = per_family_metrics(meta1, y1, pred1, proba1)
        log.info("1s deep-dive subset: n=%s R=%.4f FPR=%.5f",
                 f"{len(y1):,}", m1["recall"], m1["fpr"])

        # FN evidence in the 1s window: how much of the flow had arrived?
        fn1_mask = (y1 == 1) & (pred1 == 0)
        deep_rows = []
        for fam in np.unique(meta1["family"][y1 == 1]):
            fm = (meta1["family"].to_numpy() == fam) & (y1 == 1)
            det = fm & ~fn1_mask
            r = {"family": fam, "n_1s_flows": int(fm.sum()),
                 "recall_1s": float(pred1[fm].mean()) if fm.any() else float("nan"),
                 "n_fn_1s": int((fm & fn1_mask).sum())}
            ev1 = {"n_packets_eff": n_pkt_eff, **{c: X1[c].to_numpy() for c in
                  ("flow_duration_s", "flow_packets_s", "syn_count", "ack_count",
                   "flow_iat_mean")}}
            for f, arr in ev1.items():
                r[f"{f}_fn_med"] = float(np.median(arr[fm & fn1_mask])) \
                    if (fm & fn1_mask).any() else None
                r[f"{f}_det_med"] = float(np.median(arr[det])) \
                    if det.any() else None
            deep_rows.append(r)
        deep_df = pd.DataFrame(deep_rows)
        deep_df.to_csv(RESEARCH_DIR / "error_1s_family_evidence.csv", index=False)
        log.info("\n%s", deep_df.to_string(index=False))

    # ---------------- save ----------------------------------------------------
    with timed_stage(4, 4, "Writing error-analysis outputs"):
        fam_json = fam_df.where(pd.notna(fam_df), None).to_dict(orient="records")
        deep_json = deep_df.where(pd.notna(deep_df), None).to_dict(orient="records")
        out = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "seed": 42,
            "scope": "evaluation reads only: frozen model scored existing tables; "
                     "no refit, no threshold change, official artifacts untouched",
            "consistency_check_vs_official": {
                "passed": bool(consistent),
                "official_source": "experiments/final_test_results.csv (unchanged)",
                "rederived": {k: float(m[k]) for k in
                              ("precision", "recall", "f1", "fpr", "fnr")},
            },
            "final_test_errors": {
                "n_fn": int(fn_mask.sum()), "n_fp": int(fp_mask.sum()),
                "fn_by_family": {r["family"]: {"n_fn": r["n_fn"], "fn_rate": r["fn_rate"],
                                               "n_flows": r["n_flows"]} for r in fam_json},
                "fp_profile": fp_profile,
            },
            "early_1s_deep_dive": {
                "captures": sel_caps,
                "metrics": {k: float(v) for k, v in m1.items()},
                "family_evidence": deep_json,
                "method": "causal 1s re-extraction (early_detection.extract_window_rows) "
                          "scored with the frozen pipeline; t_op=0.5",
            },
            "taxonomy_note": "see reports/error_analysis_report.md for the interpreted "
                             "failure-mode table (evidence -> cause -> implication -> "
                             "future mitigation, no mitigation claimed as implemented)",
        }
        json_dump(out, Path("reports/error_analysis_results.json"))
        log.info("ANALYSIS 3 DONE in %.1fs", time.perf_counter() - t0)


if __name__ == "__main__":
    main()
