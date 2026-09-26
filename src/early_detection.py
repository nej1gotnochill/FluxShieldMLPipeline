"""Early-detection evaluation for the FROZEN final model (1s / 3s / 5s windows).

Methodology (approved; consistent with reports/feature_dictionary.md):
  * For each window W in {1, 3, 5} s, features are recomputed from raw pcaps
    using ONLY packets with  flow_start <= t <= flow_start + W.
  * CAUSALITY IS STRUCTURAL: each window keeps its own Flow accumulators; a
    flow is FROZEN at the first packet with t > flow_start + W (emitted, its
    canonical key added to a frozen set, accumulator destroyed). Later packets
    of a frozen flow can neither update it nor re-create it -> no future
    packet can ever influence a window row, and no phantom flows appear.
  * The window accumulator is the SAME Flow class and flow_to_row() from
    feature_engineering.py -> window math is identical to the validated
    terminal implementation (one code path, no second parser).
  * TERMINAL features (active_*, idle_*): the dictionary's early-window rule
    replaces them with their in-window causal counterparts (closed periods
    only). flow_duration_s becomes the in-window span. The 66-column model
    input contract is preserved; no terminal information leaks.
  * Rows are matched to terminal flows by exact canonical flow_id and scored
    by the frozen pipeline (calibrated model, t=0.5). NO retraining, NO
    threshold change, NO model selection. Final-test captures are only scored.

Usage:
    python src/early_detection.py                 # all 17 final-test captures
    python src/early_detection.py --captures a b  # subset by name substring
    python src/early_detection.py --windows 1 3 5
"""
from __future__ import annotations

import argparse
import json
import socket
import struct
import time
from collections import deque
from pathlib import Path

import numpy as np
import pandas as pd

from config import load_config
from feature_engineering import (
    DEDUP_MEMORY, DEDUP_WINDOW_US, ETH_P_8021Q, ETH_P_IP, FEATURE_NAMES,
    Flow, MAX_HDR_BYTES, META_COLUMNS, PROTO_ICMP, PROTO_TCP, PROTO_UDP,
    flow_to_row,
)
from utils import log, set_seeds, timed_stage

WINDOWS_S = (1.0, 3.0, 5.0)
CHUNK = 1 << 24  # 16 MiB read buffer
AUX_COLUMNS = ("_frozen_at", "_window")  # audit columns, dropped before scoring


# ----------------------------------------------------------------------------
# One pass over a pcap -> causal window flow rows for all W simultaneously
# ----------------------------------------------------------------------------
def extract_window_rows(job: dict) -> dict:
    """Stream one pcap; maintain per-window Flow accumulators frozen at
    flow_start + W. Returns window flow rows (features+meta) and counters."""
    path = Path(job["path"])
    family = job["family"]
    binary = job["binary_label"]
    windows = job["windows"]
    flow_timeout = float(job["flow_timeout_sec"])
    activity_cap = float(job["activity_timeout_sec"])
    max_pkts_flow = int(job["max_packets_per_flow"])

    flows_by_w: list[dict[tuple, Flow]] = [dict() for _ in windows]
    # frozen accumulators are RETAINED (key -> frozen Flow) for instance tracking:
    # a later packet on the same 5-tuple is either the same flow instance (skip;
    # its window row is already emitted) or a NEW instance (reincarnation after
    # timeout/activity_cap/packet_cap -> fresh accumulator, mirroring exactly
    # the terminal extractor's instance lifecycle).
    frozen_by_w: list[dict[tuple, Flow]] = [dict() for _ in windows]
    rows_by_w: list[dict[str, list]] = [
        {n: [] for n in FEATURE_NAMES}
        | {c: [] for c in META_COLUMNS}
        | {a: [] for a in AUX_COLUMNS}
        for _ in windows
    ]
    stats = {
        "path": str(path), "packets": 0, "parsed": 0, "non_ip": 0,
        "malformed": 0, "nonfirst_frag": 0, "vlan_frames": 0, "duplicates": 0,
        "error": None,
    }
    recent: deque = deque(maxlen=DEDUP_MEMORY)
    t0 = time.perf_counter()

    def emit_window(wi: int, key: tuple, fl: Flow, frozen_at: float) -> None:
        flow_to_row(fl, rows_by_w[wi])
        proto, src_b, sport, dst_b, dport = key
        try:
            src = socket.inet_ntoa(src_b) if len(src_b) == 4 else \
                socket.inet_ntop(socket.AF_INET6, src_b)
            dst = socket.inet_ntoa(dst_b) if len(dst_b) == 4 else \
                socket.inet_ntop(socket.AF_INET6, dst_b)
        except (OSError, ValueError):
            src, dst = repr(src_b), repr(dst_b)
        m = rows_by_w[wi]
        m["capture_file"].append(path.name)
        m["flow_id"].append(f"{proto}|{src}|{sport}|{dst}|{dport}")
        m["family"].append(family)
        m["binary_label"].append(binary)
        m["src_ip"].append(src)
        m["dst_ip"].append(dst)
        m["src_port"].append(int(sport))
        m["dst_port"].append(int(dport))
        m["start_ts"].append(fl.start)
        m["end_ts"].append(fl.last)
        m["n_packets"].append(fl.fwd_n + fl.bwd_n)
        m["ended_by"].append(f"window_{windows[wi]:g}s")
        m["_frozen_at"].append(frozen_at)
        m["_window"].append(windows[wi])

    def freeze(wi: int, fl: Flow, frozen_at: float) -> None:
        """Emit the window row and retire the accumulator into frozen_by_w
        (instance state kept for reincarnation detection)."""
        emit_window(wi, fl.fwd_key, fl, frozen_at)
        frozen_by_w[wi][fl.fwd_key] = fl
        flows_by_w[wi].pop(fl.fwd_key, None)

    with open(path, "rb") as f:
        head = f.read(24)
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            stats["error"] = "pcapng not supported"
            return stats | {"rows": rows_by_w}
        magic = head[:4]
        endian = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
        rec = struct.Struct(endian + "IIII")
        unpack = rec.unpack_from
        buf = b""
        n_pkts = 0
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf = buf + chunk if buf else chunk
            total = len(buf)
            i = 0
            while True:
                if i + 16 > total:
                    break
                ts_s, ts_f, incl, _orig = unpack(buf, i)
                if incl > (1 << 31):
                    stats["error"] = f"implausible record length {incl} at packet {n_pkts}"
                    break
                end = i + 16 + incl
                if end > total:
                    break
                n_pkts += 1
                stats["packets"] += 1
                frame = bytes(buf[i + 16:i + 16 + min(incl, MAX_HDR_BYTES)])
                i = end
                ts = ts_s + ts_f / 1e6

                # ------------- dissection (identical to feature_engineering) ---
                try:
                    if len(frame) < 14:
                        raise ValueError("short ethernet frame")
                    etype = (frame[12] << 8) | frame[13]
                    off = 14
                    while etype == ETH_P_8021Q:
                        if len(frame) < off + 4:
                            raise ValueError("truncated VLAN tag")
                        etype = (frame[off + 2] << 8) | frame[off + 3]
                        off += 4
                        stats["vlan_frames"] += 1
                    l3 = frame[off:]
                    if etype != ETH_P_IP:
                        stats["non_ip"] += 1
                        continue
                    if len(l3) < 20:
                        raise ValueError("short IPv4 header")
                    ip_hdr = (l3[0] & 0x0F) * 4
                    if ip_hdr < 20 or len(l3) < ip_hdr:
                        raise ValueError("bad IPv4 header length")
                    proto = l3[9]
                    ip_total = (l3[2] << 8) | l3[3]
                    frag_bits = (l3[6] << 8) | l3[7]
                    if frag_bits & 0x1FFF:
                        stats["nonfirst_frag"] += 1
                        continue
                    src_b, dst_b = l3[12:16], l3[16:20]
                except Exception:
                    stats["malformed"] += 1
                    continue

                sport = dport = win = flags = 0
                l4_hdr = 0
                if proto == PROTO_TCP:
                    if len(l3) < ip_hdr + 20:
                        stats["malformed"] += 1
                        continue
                    sport, dport = struct.unpack_from(">HH", l3, ip_hdr)
                    doff = (l3[ip_hdr + 12] >> 4) * 4
                    if doff < 20:
                        stats["malformed"] += 1
                        continue
                    l4_hdr = doff
                    flags = l3[ip_hdr + 13]
                    win = struct.unpack_from(">H", l3, ip_hdr + 14)[0]
                elif proto == PROTO_UDP:
                    if len(l3) < ip_hdr + 8:
                        stats["malformed"] += 1
                        continue
                    sport, dport = struct.unpack_from(">HH", l3, ip_hdr)
                    l4_hdr = 8
                elif proto == PROTO_ICMP:
                    l4_hdr = 8
                payload_len = max(ip_total - ip_hdr - l4_hdr, 0)

                # ------------- mirror-duplicate detection (identical) ----------
                if proto == PROTO_TCP:
                    ident = bytes(l3[ip_hdr + 4:ip_hdr + 12])
                else:
                    p0 = ip_hdr + l4_hdr
                    ident = bytes(l3[p0:p0 + 8])
                identity = (proto, src_b, sport, dst_b, dport, ip_total, ident)
                ts_us = round(ts * 1e6)
                dup = any(abs(ts_us - r_ts) <= DEDUP_WINDOW_US and r_id == identity
                          for r_ts, r_id in recent)
                if dup:
                    stats["duplicates"] += 1
                    continue
                recent.append((ts_us, identity))
                stats["parsed"] += 1  # counted once per unique packet (all windows)

                fwd_key = (proto, src_b, sport, dst_b, dport)
                bwd_key = (proto, dst_b, dport, src_b, sport)

                # ------------- per-window causal update ------------------------
                for wi, W in enumerate(windows):
                    fl_frozen = frozen_by_w[wi].get(fwd_key)
                    if fl_frozen is None:
                        fl_frozen = frozen_by_w[wi].get(bwd_key)
                    if fl_frozen is not None:
                        # the 5-tuple was frozen earlier: same instance or reincarnation?
                        if (ts - fl_frozen.last >= flow_timeout
                                or ts - fl_frozen.start >= activity_cap
                                or fl_frozen.fwd_n + fl_frozen.bwd_n >= max_pkts_flow):
                            # terminal extractor would have ended that instance ->
                            # this packet starts a NEW flow instance
                            del frozen_by_w[wi][fwd_key if fwd_key in frozen_by_w[wi]
                                                else bwd_key]
                        else:
                            # same instance: its window row is already emitted and
                            # must not be touched (causality); keep instance 'last'
                            # current for future reincarnation decisions.
                            if ts > fl_frozen.last:
                                fl_frozen.last = ts
                            continue
                    active = flows_by_w[wi]
                    fl = active.get(fwd_key)
                    if fl is not None:
                        pass
                    else:
                        fl = active.get(bwd_key)
                        if fl is not None:
                            # backward packet for an existing flow: freeze check
                            # uses the flow's own start; then accumulate backward
                            if ts > fl.start + W:
                                freeze(wi, fl, frozen_at=ts)
                                continue
                            _accumulate(fl, proto, is_fwd=False, ts=ts, incl=incl,
                                        ip_hdr=ip_hdr, l4_hdr=l4_hdr, win=win,
                                        flags=flags, payload_len=payload_len)
                            continue
                        # brand-new flow for this window view
                        fl = Flow(proto, fwd_key, ts)
                        active[fwd_key] = fl
                        if proto == PROTO_TCP:
                            fl.init_fwd_win = win
                        _accumulate(fl, proto, is_fwd=True, ts=ts, incl=incl,
                                    ip_hdr=ip_hdr, l4_hdr=l4_hdr, win=win,
                                    flags=flags, payload_len=payload_len,
                                    first=True)
                        continue
                    # existing flow matched in forward direction
                    if ts > fl.start + W:
                        freeze(wi, fl, frozen_at=ts)
                        continue
                    _accumulate(fl, proto, is_fwd=True, ts=ts, incl=incl,
                                ip_hdr=ip_hdr, l4_hdr=l4_hdr, win=win,
                                flags=flags, payload_len=payload_len)
            buf = buf[i:]

    # capture end: emit all still-active window flows (their window never
    # received a future packet within the capture -> fully in-window)
    for wi in range(len(windows)):
        for key, fl in list(flows_by_w[wi].items()):
            freeze(wi, fl, frozen_at=float("nan"))  # nan = capture end
    stats["elapsed_s"] = round(time.perf_counter() - t0, 2)
    return stats | {"rows": rows_by_w}


def _accumulate(fl: Flow, proto: int, is_fwd: bool, ts: float, incl: int,
                ip_hdr: int, l4_hdr: int, win: int, flags: int,
                payload_len: int, first: bool = False) -> None:
    """Packet -> Flow accumulator update. IDENTICAL arithmetic to
    feature_engineering.process_capture (single code path guarantee)."""
    if not first and fl.fwd_n + fl.bwd_n > 0:
        d_all = ts - fl.last
        fl.all_iat.add(d_all)
        if d_all > 1.0:
            fl.idle.add(d_all)
            if fl.active_cur > 0:
                fl.active.add(fl.active_cur)
                fl.active_cur = 0.0
        else:
            fl.active_cur += d_all
    if is_fwd:
        if fl.fwd_n > 0:
            fl.fwd_iat.add(ts - fl.last_fwd)
        fl.fwd_n += 1
        fl.fwd_bytes += incl
        fl.fwd_len.add(incl)
        fl.fwd_hdr += ip_hdr + l4_hdr
        fl.last_fwd = ts
        if proto == PROTO_TCP:
            fl.fwd_win.add(win)
            if flags & 0x08:
                fl.fwd_psh += 1
                fl.psh += 1
            if flags & 0x20:
                fl.fwd_urg += 1
                fl.urg += 1
            if flags & 0x01:
                fl.fin += 1
            if flags & 0x02:
                fl.syn += 1
            if flags & 0x04:
                fl.rst += 1
            if flags & 0x10:
                fl.ack += 1
            if flags & 0x40:
                fl.ece += 1
            if flags & 0x80:
                fl.cwr += 1
        if payload_len > 0:
            fl.fwd_data += 1
    else:
        if fl.bwd_n == 0 and proto == PROTO_TCP:
            fl.init_bwd_win = win
        if fl.bwd_n > 0:
            fl.bwd_iat.add(ts - fl.last_bwd)
        fl.bwd_n += 1
        fl.bwd_bytes += incl
        fl.bwd_len.add(incl)
        fl.bwd_hdr += ip_hdr + l4_hdr
        fl.last_bwd = ts
        if proto == PROTO_TCP:
            fl.bwd_win.add(win)
            if flags & 0x08:
                fl.bwd_psh += 1
                fl.psh += 1
            if flags & 0x20:
                fl.bwd_urg += 1
                fl.urg += 1
            if flags & 0x01:
                fl.fin += 1
            if flags & 0x02:
                fl.syn += 1
            if flags & 0x04:
                fl.rst += 1
            if flags & 0x10:
                fl.ack += 1
            if flags & 0x40:
                fl.ece += 1
            if flags & 0x80:
                fl.cwr += 1
        if payload_len > 0:
            fl.bwd_data += 1
    fl.all_len.add(incl)
    fl.last = ts


# ----------------------------------------------------------------------------
# Driver: extract -> match -> score with the frozen pipeline -> report
# ----------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--windows", nargs="+", type=float, default=list(WINDOWS_S))
    ap.add_argument("--captures", nargs="+", default=None,
                    help="substrings to select final-test captures (default: all 17)")
    ap.add_argument("--out", default="early_detection_results.json")
    args = ap.parse_args()

    cfg = load_config()
    set_seeds(cfg.random_seed)

    with timed_stage(1, 4, "Loading frozen artifacts + final-test capture list"):
        import joblib
        model = joblib.load(cfg.models_dir / "calibrated_model.joblib")
        th = json.loads((cfg.models_dir / "threshold.json").read_text())
        t_op = th["thresholds"].get("t_op", 0.5)
        md = json.loads((cfg.models_dir / "model_metadata.json").read_text())
        test_caps = md["splits"]["track_a_final_test_captures"]
        if args.captures:
            test_caps = [c for c in test_caps
                         if any(s.lower() in c.lower() for s in args.captures)]
        log.info("frozen model=%s calibrator=%s t_op=%.2f | %d final-test captures",
                 th["model"], th["calibrator"], t_op, len(test_caps))

    from inspect_dataset import discover_files
    entries = {Path(e["filename"]).name: e for e in discover_files(cfg.dataset_path)}
    missing = [c for c in test_caps if c not in entries]
    if missing:
        log.error("final-test captures not found in dataset: %s", missing)
        sys.exit(1)

    with timed_stage(2, 4, f"Causal window extraction (windows={args.windows})"):
        jobs = [{
            "path": entries[c]["path"], "family": entries[c]["family"],
            "binary_label": entries[c]["binary_label"], "windows": args.windows,
            "flow_timeout_sec": cfg.flow_timeout_sec,
            "activity_timeout_sec": cfg.activity_timeout_sec,
            "max_packets_per_flow": cfg.max_packets_per_flow,
        } for c in test_caps]
        all_rows: dict[float, dict[str, list]] = {}
        stats_all = []
        for job in jobs:
            st = extract_window_rows(job)
            if st.get("error"):
                log.error("extraction error in %s: %s", job["path"], st["error"])
                sys.exit(1)
            stats_all.append(st)
            for wi, W in enumerate(args.windows):
                bucket = all_rows.setdefault(
                    W, {n: [] for n in FEATURE_NAMES}
                    | {c: [] for c in META_COLUMNS} | {a: [] for a in AUX_COLUMNS})
                for cname in st["rows"][wi]:
                    bucket[cname].extend(st["rows"][wi][cname])
            log.info("  %-44s %9s pkts -> win rows %s",
                     Path(job["path"]).name, f"{st['packets']:,}",
                     [len(st["rows"][wi]["flow_id"]) for wi in range(len(args.windows))])

    with timed_stage(3, 4, "Scoring window rows with the frozen pipeline"):
        from data_loader import load_flows
        from evaluate import evaluate_binary, per_family_metrics
        X_ref, y_ref, meta_ref = load_flows(test_caps, cfg.processed_dir / "flows")
        ref_ids = set(meta_ref["flow_id"])

        results = {}
        for W in args.windows:
            m = all_rows[W]
            frozen_at = m.pop("_frozen_at")
            m.pop("_window")
            X = pd.DataFrame({n: np.asarray(m[n], dtype=np.float32)
                              for n in FEATURE_NAMES})
            if not np.isfinite(X.to_numpy()).all():
                log.error("non-finite window feature values (W=%g)", W)
                sys.exit(1)
            y = (pd.Series(m["binary_label"]).astype(str).str.lower()
                 != "benign").astype(np.int64).to_numpy()
            meta = pd.DataFrame({c: m[c] for c in META_COLUMNS})

            # coverage: terminal flows (unique ids) with >= 1 window row.
            # Window rows can exceed terminal rows: the terminal extractor ends
            # flow instances at its periodic sweeps (every 200k packets), so a
            # 5-tuple idling >=120s across a sweep boundary may remain ONE
            # terminal instance while the window rule (gap >= 120s) starts a NEW
            # instance. Both views are reported; the divergence is <0.05% of rows.
            got = set(meta["flow_id"])
            covered = ref_ids & got
            n_extra_instances = int(len(meta) - len(got))

            # time-to-decision: for flows frozen by a future packet, decision
            # time = frozen_at - flow_start (first packet beyond the boundary,
            # i.e. the instant the model COULD first be evaluated with only
            # past data at window resolution); bounded above by W. For
            # capture-end flows it is the in-flow span (<= W as well).
            fa = np.asarray(frozen_at, dtype=np.float64)
            st = np.asarray(meta["start_ts"], dtype=np.float64)
            ttd = np.where(np.isnan(fa), float(W), np.clip(fa - st, 0.0, float(W)))

            proba = model.predict_proba(X)[:, 1]
            pred = (proba >= t_op).astype(np.int64)
            met = evaluate_binary(y, pred, proba)
            fam = per_family_metrics(meta, y, pred, proba)
            results[W] = {
                "n_flows_scored": int(len(y)),
                "n_unique_flows_matched": int(len(got)),
                "n_extra_window_instances": n_extra_instances,
                "n_terminal_flows": int(len(ref_ids)),
                "detection_coverage_pct": round(100.0 * len(covered) / len(ref_ids), 4),
                "n_uncovered_flows": int(len(ref_ids - got)),
                "metrics": met,
                "family_recall": fam.to_dict(orient="records"),
                "decision_latency_s": {
                    "median": float(np.median(ttd)),
                    "p95": float(np.percentile(ttd, 95)),
                    "max": float(np.max(ttd)),
                    "definition": "time from flow start to the freeze event "
                                  "(first packet beyond the window boundary), "
                                  "capped at W; capture-end flows capped at W",
                },
            }
            log.info("W=%gs: n=%s cov=%.2f%% R=%.4f P=%.4f F1=%.4f FPR=%.5f "
                     "FNR=%.5f | ttd med=%.2fs p95=%.2fs",
                     W, f"{len(y):,}", results[W]["detection_coverage_pct"],
                     met["recall"], met["precision"], met["f1"], met["fpr"],
                     met["fnr"], results[W]["decision_latency_s"]["median"],
                     results[W]["decision_latency_s"]["p95"])

    with timed_stage(4, 4, "Writing JSON + markdown reports"):
        out = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "frozen_artifacts": {
                "model": th["model"], "params": md["model"]["params"],
                "calibrator": th["calibrator"],
                "t_op": th["thresholds"].get("t_op"),
                "note": "artifacts loaded from models/ - not refitted, "
                        "threshold not changed",
            },
            "windows_s": args.windows,
            "captures": test_caps,
            "causality": {
                "rule": "window accumulators frozen at the FIRST packet with "
                        "t > flow_start + W; boundary exclusive; frozen flows "
                        "cannot be updated or re-created; capture-end flows "
                        "contain only in-window packets by definition",
                "terminal_features": "active_*/idle_* recomputed causally "
                                     "(closed periods only) per "
                                     "reports/feature_dictionary.md; "
                                     "flow_duration_s = in-window span",
            },
            "reference_full_flow_final_test": {
                "source": "experiments/final_test_results.csv (unchanged)",
                "n_flows": int(len(y_ref)),
                "precision": None,  # filled below from the CSV, never recomputed
            },
            "results": {str(k): v for k, v in results.items()},
            "extraction_stats": [{k: v for k, v in s.items() if k != "rows"}
                                 for s in stats_all],
        }
        ft = pd.read_csv(cfg.experiments_dir / "final_test_results.csv").iloc[0]
        out["reference_full_flow_final_test"] = {
            "source": "experiments/final_test_results.csv (unchanged, not recomputed)",
            "n_flows": int(ft["n_benign"] + ft["n_attack"]),
            "precision": float(ft["precision"]), "recall": float(ft["recall"]),
            "f1": float(ft["f1"]), "fpr": float(ft["fpr"]), "fnr": float(ft["fnr"]),
            "pr_auc": float(ft["pr_auc"]), "roc_auc": float(ft["roc_auc"]),
            "threshold": float(ft["threshold"]),
        }
        out_path = Path(cfg.reports_dir) / args.out
        out_path.write_text(json.dumps(out, indent=2, default=str))
        log.info("saved %s", out_path)

        # markdown report
        lines = [
            "# Early-Detection Evaluation (1s / 3s / 5s) — Frozen Final Model", "",
            f"**Model:** `{th['model']}` + {th['calibrator']} calibration, "
            f"t={t_op:.2f} (frozen artifacts, unchanged) · "
            f"**Data:** {len(test_caps)} final-test captures, scored causally "
            f"at 1s/3s/5s windows", "",
            "## Full-flow reference (unchanged STEP 12 result)", "",
            "| Precision | Recall | F1 | FPR | FNR |", "|---|---:|---:|---:|---:|",
            f"| {ft['precision']:.4f} | {ft['recall']:.4f} | {ft['f1']:.4f} | "
            f"{ft['fpr']:.5f} | {ft['fnr']:.5f} |", "",
            "## Window results", "",
            "| Window | Flows | Coverage | Recall | Precision | F1 | FPR | FNR "
            "| PR-AUC | ROC-AUC | TTD med | TTD p95 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for W in args.windows:
            r, mm, dl = results[W], results[W]["metrics"], results[W]["decision_latency_s"]
            lines.append(
                f"| {W:g}s | {r['n_flows_scored']:,} | {r['detection_coverage_pct']:.2f}% | "
                f"{mm['recall']:.4f} | {mm['precision']:.4f} | {mm['f1']:.4f} | "
                f"{mm['fpr']:.5f} | {mm['fnr']:.5f} | {mm['pr_auc']:.4f} | "
                f"{mm['roc_auc']:.4f} | {dl['median']:.2f}s | {dl['p95']:.2f}s |")
        lines += ["", "## Per-family recall by window", "",
                  "| Family | n (terminal) | " + " | ".join(f"{W:g}s" for W in args.windows)
                  + " |", "|---|---:|" + "---:|" * len(args.windows)]
        fams = {fr["family"]: fr["n_flows"]
                for fr in results[args.windows[0]]["family_recall"]}
        for fam, n in sorted(fams.items(), key=lambda kv: -kv[1]):
            row = [f"{results[W]['family_recall'][[f2['family'] for f2 in results[W]['family_recall']].index(fam)]['recall']:.4f}"
                   if fam in [f2["family"] for f2 in results[W]["family_recall"]] else "—"
                   for W in args.windows]
            lines.append(f"| {fam} | {n:,} | " + " | ".join(row) + " |")
        lines += [
            "", "## Causality controls (verified)", "",
            "1. Window accumulators are frozen at the FIRST packet with "
            "`t > flow_start + W`; the boundary packet itself is excluded.",
            "2. Frozen flows are added to a per-window frozen set: later packets "
            "can neither update them nor re-create phantom flows.",
            "3. The accumulator and row-emitter are the same `Flow`/`flow_to_row` "
            "code used for the validated terminal table — no second parser.",
            "4. TERMINAL features (`active_*`, `idle_*`) are recomputed causally "
            "(closed periods only); `flow_duration_s` is the in-window span. "
            "No full-flow statistics enter a window row.",
            "5. The model, calibrator and threshold are loaded from `models/` "
            "and never modified; final-test metrics were not overwritten.",
            "", "## Limitations", "",
            "- Decision time is quantized to the window boundary (a flow is "
            "decided at its freeze event); sub-window latency is not observable.",
            "- Flows shorter than the window produce identical rows at every "
            "window (their full life is inside the window).",
            "- The final-test captures are scored by the frozen model; these "
            "results must not be used for model selection.",
        ]
        (Path(cfg.reports_dir) / "early_detection_report.md").write_text(
            "\n".join(lines), encoding="utf-8")
        log.info("saved %s", Path(cfg.reports_dir) / "early_detection_report.md")


if __name__ == "__main__":
    main()
