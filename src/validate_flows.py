"""Flow-table validation for DDoS-AT-2022 extraction.

1. Global accounting identity: for every capture,
       sum(n_packets over flows) == packets - duplicates - non_ip - malformed - nonfirst_frag
   (parsed packets are added to exactly one flow; every flow is eventually emitted).
2. Duplicate flow_id check within each capture (re-started flows after timeout/cap).
3. Sampled-flow verification: re-parse the source pcap ONCE, re-derive a sample of
   flows from raw packets (independent aggregation path), and compare counts/bytes/
   duration/flags against the parquet rows.
4. Distribution summary: flows per family, per capture, duration and packet percentiles.
5. Walk-forward fold proposal (chronological capture ordering by first packet time).

Read-only with respect to the raw dataset.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

from config import load_config
from utils import log

DEDUP_WINDOW_US = 2
MAX_HDR_BYTES = 128
CHUNK = 1 << 25
ETH_P_8021Q = 0x8100
ETH_P_IP = 0x0800


# ---------------------------------------------------------------------------
# light pcap scanner: yields (ts, incl_len, frame_bytes) for IPv4 Ethernet frames
# ---------------------------------------------------------------------------
def iter_ipv4_frames(path: Path):
    with open(path, "rb") as f:
        head = f.read(24)
        magic = head[:4]
        endian = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
        rec = struct.Struct(endian + "IIII")
        buf = b""
        n = 0
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
                ts_s, ts_f, incl, _orig = rec.unpack_from(buf, i)
                if incl > (1 << 31):
                    break
                end = i + 16 + incl
                if end > total:
                    break
                n += 1
                frame = bytes(buf[i + 16:i + 16 + min(incl, MAX_HDR_BYTES)])
                i = end
                ts = ts_s + ts_f / 1e6
                if len(frame) < 14:
                    continue
                etype = (frame[12] << 8) | frame[13]
                off = 14
                while etype == ETH_P_8021Q:
                    if len(frame) < off + 4:
                        break
                    etype = (frame[off + 2] << 8) | frame[off + 3]
                    off += 4
                l3 = frame[off:]
                if etype != ETH_P_IP or len(l3) < 20:
                    continue
                yield ts, incl, l3
            buf = buf[i:]


def parse_l4(l3: bytes):
    """Return (proto, src_b, dst_b, sport, dport, win, flags, ip_total, ident_bytes, ip_hdr, l4_hdr, payload_len)."""
    ip_hdr = (l3[0] & 0x0F) * 4
    if ip_hdr < 20 or len(l3) < ip_hdr:
        return None
    proto = l3[9]
    ip_total = (l3[2] << 8) | l3[3]
    frag_bits = (l3[6] << 8) | l3[7]
    if frag_bits & 0x1FFF:
        return None
    src_b, dst_b = l3[12:16], l3[16:20]
    sport = dport = win = flags = 0
    l4_hdr = 0
    if proto == 6:
        if len(l3) < ip_hdr + 20:
            return None
        sport, dport = struct.unpack_from(">HH", l3, ip_hdr)
        doff = (l3[ip_hdr + 12] >> 4) * 4
        if doff < 20:
            return None
        l4_hdr = doff
        flags = l3[ip_hdr + 13]
        win = struct.unpack_from(">H", l3, ip_hdr + 14)[0]
        ident = bytes(l3[ip_hdr + 4:ip_hdr + 12])
    elif proto == 17:
        if len(l3) < ip_hdr + 8:
            return None
        sport, dport = struct.unpack_from(">HH", l3, ip_hdr)
        l4_hdr = 8
        ident = bytes(l3[ip_hdr + 8:ip_hdr + 16])
    elif proto == 1:
        l4_hdr = 8
        ident = bytes(l3[ip_hdr + 8:ip_hdr + 16])
    else:
        ident = b""
    payload_len = max(ip_total - ip_hdr - l4_hdr, 0)
    return proto, src_b, dst_b, sport, dport, win, flags, ip_total, ident, ip_hdr, l4_hdr, payload_len


def accounting_from_logs(reports_dir: Path):
    """Parse per-file extraction counters from the batch logs."""
    pat = re.compile(
        r"([^|]+?\.pcap)\s+([\d,]+) pkts\s+\|\s+([\d,]+) flows\s+\|"
        r"\s*[\d.]+s\s+\|\s+[\d.]+k pkt/s\s+\|\s+rss<=(\d+)MB\s+\|\s*"
        r"vlan=(\d+) dup=(\d+) non_ip=(\d+) malformed=(\d+) frag=(\d+)")
    out = {}
    for logf in ["extraction_benign.log", "extraction_attacks.log"]:
        p = reports_dir / logf
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            m = pat.search(line)
            if not m:
                continue
            name = m.group(1).strip()
            out[name] = {
                "packets": int(m.group(2).replace(",", "")),
                "flows": int(m.group(3).replace(",", "")),
                "rss_mb": int(m.group(4)),
                "vlan": int(m.group(5)),
                "dup": int(m.group(6)),
                "non_ip": int(m.group(7)),
                "malformed": int(m.group(8)),
                "frag": int(m.group(9)),
            }
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures", nargs="+", default=None,
                    help="capture name substrings to sample flows from (default: httperf_2nd, slow header_1st, tcp syn flood)")
    ap.add_argument("--n-flows", type=int, default=12, help="flows to re-derive per capture")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    cfg = load_config()
    flows_dir = Path(cfg.processed_dir) / "flows"
    acc = accounting_from_logs(Path(cfg.reports_dir))

    # ---- 1. global accounting identity -------------------------------------
    log.info("[1/5] Global packet-accounting identity")
    total_rows = 0
    n_match = n_skip = 0
    for f in sorted(flows_dir.glob("*.parquet")):
        df = pd.read_parquet(f, columns=["n_packets", "capture_file"])
        s = int(df["n_packets"].sum())
        total_rows += s
        a = acc.get(df["capture_file"].iloc[0])
        if a is None:
            n_skip += 1
            log.error("  NO COUNTERS %-45s (validator bug or missing log line)", df["capture_file"].iloc[0])
            continue
        expected = a["packets"] - a["dup"] - a["non_ip"] - a["malformed"] - a["frag"]
        ok = s == expected
        if ok:
            n_match += 1
            log.info("  ok      %-45s %9d packets accounted", f.name, s)
        else:
            log.error("  MISMATCH %-45s flows_pkts=%-9d expected=%-9d", f.name, s, expected)
    n_files = len(list(flows_dir.glob("*.parquet")))
    log.info("  accounting identity: %d matched, %d mismatched, %d skipped (of %d)",
             n_match, n_files - n_match - n_skip, n_skip, n_files)
    if n_match + (n_files - n_match - n_skip) != n_files or n_skip:
        log.error("  accounting check INCOMPLETE — do not trust until every capture is verified")

    # ---- 2. duplicate flow_id within capture --------------------------------
    log.info("[2/5] Duplicate flow_id check (within capture)")
    dup_ids = 0
    for f in sorted(flows_dir.glob("*.parquet")):
        df = pd.read_parquet(f, columns=["flow_id"])
        d = int(df["flow_id"].duplicated().sum())
        dup_ids += d
        if d:
            log.warning("  %-45s %d duplicate flow_ids (re-started flows)", f.name, d)
    log.info("  total duplicate flow_ids across captures: %d", dup_ids)

    # ---- 3. sampled-flow re-derivation -------------------------------------
    log.info("[3/5] Sampled-flow re-derivation from raw packets")
    if args.captures is None:
        args.captures = ["httperf_2nd", "slow header_1st", "tcp syn flood"]
    rng = np.random.default_rng(args.seed)
    all_ok = True
    for sub in args.captures:
        matches = [f for f in sorted(flows_dir.glob("*.parquet")) if sub.lower() in f.name.lower()]
        if not matches:
            log.error("  no parquet matches '%s'", sub)
            continue
        for pf in matches:
            df = pd.read_parquet(pf)
            cap = df["capture_file"].iloc[0]
            # pick flows that are unique in the capture and ended at capture end
            id_counts = df["flow_id"].value_counts()
            uniq = id_counts[id_counts == 1].index
            cand = df[df["flow_id"].isin(uniq) & (df["ended_by"] == "capture_end")].copy()
            if len(cand) == 0:
                log.warning("  %-45s no single-row capture_end flows; skipping", pf.name)
                continue
            sample = cand.sample(n=min(args.n_flows, len(cand)), random_state=int(rng.integers(1 << 30)))
            # re-derive: stream the pcap once, keep per-tuple aggregates for sampled tuples
            wanted = {}
            for _, r in sample.iterrows():
                key = (int(r["protocol"]), r["src_ip"], int(r["src_port"]), r["dst_ip"], int(r["dst_port"]))
                wanted[key] = r
            agg = {k: {"fwd_n": 0, "bwd_n": 0, "fwd_b": 0, "bwd_b": 0, "first": None, "last": None,
                       "last_fwd": None, "syn": 0, "n": 0} for k in wanted}
            # Mirror-duplicate detection must mirror the meter exactly: a single
            # bounded deque of recent (ts_us, identity) across ALL flows, not a
            # per-flow slot. Interleaving (A, B, A', B') defeats per-flow slots.
            from collections import deque
            DEDUP_MEMORY_V = 128
            recent: deque = deque(maxlen=DEDUP_MEMORY_V)
            pcap_path = Path(cfg.dataset_path) / str(pf).split("flows")[0]  # placeholder
            # locate the raw capture via the inventory map
            src_path = None
            for e in json.loads((Path(cfg.reports_dir) / "dataset_inventory.json").read_text(encoding="utf-8"))["files"]:
                if e["filename"] == cap:
                    src_path = Path(e["path"])
                    break
            if src_path is None:
                log.error("  raw capture %s not found in inventory", cap)
                continue
            for ts, incl, l3 in iter_ipv4_frames(src_path):
                p = parse_l4(l3)
                if p is None:
                    continue
                proto, src_b, dst_b, sport, dport, win, flags, ip_total, ident, ip_hdr, l4_hdr, plen = p
                s_ip = ".".join(map(str, src_b))
                d_ip = ".".join(map(str, dst_b))
                key = (proto, s_ip, sport, d_ip, dport)
                rkey = (proto, d_ip, dport, s_ip, sport)
                if key not in wanted and rkey not in wanted:
                    continue
                k = key if key in wanted else rkey
                fwd = key in wanted
                ts_us = round(ts * 1e6)
                rid = (proto, src_b, sport, dst_b, dport, ip_total, ident)
                dup = any(abs(ts_us - r_ts) <= DEDUP_WINDOW_US and r_id == rid
                          for r_ts, r_id in recent)
                if dup:
                    continue
                recent.append((ts_us, rid))
                a = agg[k]
                a["n"] += 1
                if a["first"] is None:
                    a["first"] = ts
                a["last"] = ts
                if fwd:
                    a["fwd_n"] += 1
                    a["fwd_b"] += incl
                    a["last_fwd"] = ts
                else:
                    a["bwd_n"] += 1
                    a["bwd_b"] += incl
                if proto == 6 and (flags & 0x02):
                    a["syn"] += 1
            # compare
            for k, r in wanted.items():
                a = agg[k]
                dur = (a["last"] - a["first"]) if a["last"] is not None else 0.0
                checks = {
                    "fwd_packets": a["fwd_n"], "bwd_packets": a["bwd_n"],
                    "fwd_bytes": a["fwd_b"], "bwd_bytes": a["bwd_b"],
                    "syn_count": a["syn"],
                }
                fails = []
                for col, got in checks.items():
                    exp = float(r[col])
                    if abs(got - exp) > max(1.0, 1e-3 * abs(exp)):
                        fails.append(f"{col} got={got} exp={exp}")
                if abs(dur - float(r["flow_duration_s"])) > 1e-3 * max(1.0, abs(dur)):
                    fails.append(f"dur got={dur:.6f} exp={float(r['flow_duration_s']):.6f}")
                status = "PASS" if not fails else "FAIL " + "; ".join(fails)
                if fails:
                    all_ok = False
                log.info("  %s | %s | proto=%s fwd=%d/%dB bwd=%d/%dB dur=%.4fs syn=%d",
                         status, r["flow_id"], r["protocol"],
                         a["fwd_n"], a["fwd_b"], a["bwd_n"], a["bwd_b"], dur, a["syn"])
    log.info("  sampled-flow verification: %s", "ALL PASS" if all_ok else "FAILURES PRESENT")

    # ---- 4. distributions ----------------------------------------------------
    log.info("[4/5] Flow distributions")
    fam_rows = defaultdict(int)
    fam_dur = defaultdict(list)
    fam_pkts = defaultdict(list)
    per_cap = []
    ended = defaultdict(int)
    for f in sorted(flows_dir.glob("*.parquet")):
        df = pd.read_parquet(f, columns=["family", "flow_duration_s", "n_packets", "ended_by", "start_ts"])
        fam = df["family"].iloc[0]
        fam_rows[fam] += len(df)
        fam_dur[fam].extend(df["flow_duration_s"].tolist())
        fam_pkts[fam].extend(df["n_packets"].tolist())
        per_cap.append((df["start_ts"].min(), f.name, len(df)))
        for e, c in df["ended_by"].value_counts().items():
            ended[e] += c
    log.info("  flows per family: %s", ", ".join(f"{k}={v:,}" for k, v in sorted(fam_rows.items(), key=lambda kv: -kv[1])))
    for fam in sorted(fam_dur):
        d = np.array(fam_dur[fam])
        p = np.array(fam_pkts[fam])
        log.info("  %-18s dur p50=%.4fs p90=%.3fs p99=%.2fs | pkts p50=%d p90=%d p99=%d",
                 fam, *np.percentile(d, [50, 90, 99]), *np.percentile(p, [50, 90, 99]).astype(int))
    log.info("  ended_by: %s", ", ".join(f"{k}={v:,}" for k, v in sorted(ended.items(), key=lambda kv: -kv[1])))
    per_cap.sort()
    log.info("  captures by first packet time (chronological):")
    for ts, name, n in per_cap:
        log.info("    %s  %-50s %8d flows", pd.Timestamp(ts, unit="s", tz="UTC"), name, n)

    # ---- 5. walk-forward fold proposal ---------------------------------------
    log.info("[5/5] Walk-forward fold proposal (Track A)")
    # chronological capture ordering; expanding-window folds
    caps = [name for _, name, _ in per_cap]
    n = len(caps)
    log.info("  %d captures in chronological order", n)
    for k in range(1, 4):
        cut = int(n * (0.6 + 0.1 * k))
        if cut >= n:
            break
        log.info("    fold %d: train=%d captures (first %d) -> val=1 (capture %d)", k, cut - 1, cut - 1, cut)


if __name__ == "__main__":
    main()