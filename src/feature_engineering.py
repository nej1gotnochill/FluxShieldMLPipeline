"""PCAP -> flow-level feature extraction (pilot + full modes).

Converts raw captures into a bidirectional flow table (one row per flow),
CICFlowMeter-style, using direct struct-based dissection (Ethernet ->
802.1Q/QinQ -> IPv4 -> TCP/UDP/ICMP). Designed for memory safety:

  * payload bytes are never read: only the first 128 bytes of each frame are
    copied for header parsing, lengths come from the IP header fields;
  * per-flow statistics accumulate in fixed-size float64 accumulators
    (sum/sumsq/min/max), so per-flow memory is O(1);
  * idle flows are swept periodically; if the tracked-flow table grows past a
    hard cap (spoofed-source floods), single-packet flows are flushed first;
  * flow rows are streamed to parquet in bounded row-group flushes;
  * output is one parquet file per capture with float32 feature columns.

Robustness notes (from the validated pilot):
  * 802.1Q VLAN tags are explicit: ~50% of frames in DDoS-AT-2022 captures
    carry them; dpkt-style auto-unwrap silently miscounts them.
  * Non-IP frames (ARP etc.) and non-first IP fragments are counted, never
    silently dropped into a class label.

LEAKAGE POLICY (see also reports/dataset_audit.md):
  * Source/destination IPs, ports, timestamps and capture identity are stored
    as metadata columns for joins/audits but are EXCLUDED from the feature
    vector. Ports would trivially identify attack tools in this dataset
    (e.g. "udp flood same port" vs "random port" captures).
  * Protocol number IS included (transport behavior, not identity).

Usage:
    python src/feature_engineering.py --pilot      # 5 representative captures
    python src/feature_engineering.py --files syn flood   # name substrings
    python src/feature_engineering.py --all
"""
from __future__ import annotations

import argparse
import json
import math
import os
import socket
import struct
import sys
import time
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

from config import load_config
from inspect_dataset import discover_files
from utils import log, timed_stage

# ----------------------------------------------------------------------------
# Feature schema (documented; the parquet column order follows this list)
# ----------------------------------------------------------------------------
FEATURES: list[tuple[str, str]] = [
    ("protocol", "IP protocol number (6=TCP, 17=UDP, 1=ICMP, other=IANA number)"),
    ("flow_duration_s", "last packet time - first packet time (seconds)"),
    ("fwd_packets", "packet count initiator->responder"),
    ("bwd_packets", "packet count responder->initiator"),
    ("fwd_bytes", "sum of captured frame lengths, fwd direction"),
    ("bwd_bytes", "sum of captured frame lengths, bwd direction"),
    ("fwd_len_max", "max frame length fwd"),
    ("fwd_len_min", "min frame length fwd"),
    ("fwd_len_mean", "mean frame length fwd"),
    ("fwd_len_std", "std of frame length fwd"),
    ("bwd_len_max", "max frame length bwd"),
    ("bwd_len_min", "min frame length bwd"),
    ("bwd_len_mean", "mean frame length bwd"),
    ("bwd_len_std", "std of frame length bwd"),
    ("pkt_len_max", "max frame length both directions"),
    ("pkt_len_min", "min frame length both directions"),
    ("pkt_len_mean", "mean frame length both directions"),
    ("pkt_len_std", "std of frame length both directions"),
    ("flow_iat_mean", "mean inter-arrival time, all packets (s)"),
    ("flow_iat_std", "std inter-arrival time, all packets (s)"),
    ("flow_iat_max", "max inter-arrival time, all packets (s)"),
    ("flow_iat_min", "min inter-arrival time, all packets (s)"),
    ("fwd_iat_total", "total time between first/last fwd packet (s)"),
    ("fwd_iat_mean", "mean fwd inter-arrival time (s)"),
    ("fwd_iat_std", "std fwd inter-arrival time (s)"),
    ("fwd_iat_max", "max fwd inter-arrival time (s)"),
    ("fwd_iat_min", "min fwd inter-arrival time (s)"),
    ("bwd_iat_total", "total time between first/last bwd packet (s)"),
    ("bwd_iat_mean", "mean bwd inter-arrival time (s)"),
    ("bwd_iat_std", "std bwd inter-arrival time (s)"),
    ("bwd_iat_max", "max bwd inter-arrival time (s)"),
    ("bwd_iat_min", "min bwd inter-arrival time (s)"),
    ("fwd_psh", "count of PSH-flagged packets fwd (TCP)"),
    ("bwd_psh", "count of PSH-flagged packets bwd (TCP)"),
    ("fwd_urg", "count of URG-flagged packets fwd (TCP)"),
    ("bwd_urg", "count of URG-flagged packets bwd (TCP)"),
    ("fin_count", "FIN flag count both directions (TCP)"),
    ("syn_count", "SYN flag count both directions (TCP)"),
    ("rst_count", "RST flag count both directions (TCP)"),
    ("psh_count", "PSH flag count both directions (TCP)"),
    ("ack_count", "ACK flag count both directions (TCP)"),
    ("urg_count", "URG flag count both directions (TCP)"),
    ("ece_count", "ECE flag count both directions (TCP)"),
    ("cwr_count", "CWR flag count both directions (TCP)"),
    ("fwd_header_bytes", "sum of IP+L4 header bytes fwd"),
    ("bwd_header_bytes", "sum of IP+L4 header bytes bwd"),
    ("down_up_ratio", "bwd_packets / fwd_packets"),
    ("avg_pkt_size", "mean frame length per packet (both directions)"),
    ("avg_fwd_seg", "fwd_bytes / fwd_packets"),
    ("avg_bwd_seg", "bwd_bytes / bwd_packets (0 if no bwd packets)"),
    ("init_fwd_win", "TCP window of first fwd packet"),
    ("init_bwd_win", "TCP window of first bwd packet"),
    ("fwd_data_pkts", "fwd packets carrying payload"),
    ("bwd_data_pkts", "bwd packets carrying payload"),
    ("active_mean", "mean duration of active periods (consecutive IAT <= 1s)"),
    ("active_std", "std duration of active periods"),
    ("active_max", "max active period (s)"),
    ("active_min", "min active period (s)"),
    ("idle_mean", "mean idle gap (IAT > 1s, within flow) (s)"),
    ("idle_std", "std idle gap (s)"),
    ("idle_max", "max idle gap (s)"),
    ("idle_min", "min idle gap (s)"),
    ("flow_bytes_s", "fwd_bytes + bwd_bytes per second"),
    ("flow_packets_s", "total packets per second"),
    ("fwd_win_mean", "mean TCP window size fwd"),
    ("bwd_win_mean", "mean TCP window size bwd"),
]
FEATURE_NAMES = [n for n, _ in FEATURES]

META_COLUMNS = [
    "capture_file", "flow_id", "family", "binary_label", "src_ip", "dst_ip",
    "src_port", "dst_port", "start_ts", "end_ts", "n_packets", "ended_by",
]

IDLE_GAP_S = 1.0          # gap > 1s counts as an idle period (documented above)
CHUNK = 1 << 25           # 32 MiB read buffer
MAX_HDR_BYTES = 128       # bytes copied per frame for header parsing
SWEEP_EVERY = 200_000     # packets between idle sweeps
MAX_TRACKED = 300_000     # hard cap on concurrently tracked flows
FLUSH_ROWS = 50_000       # flow rows buffered before a parquet row-group flush

ETH_P_8021Q = 0x8100
ETH_P_IP = 0x0800
ETH_P_IP6 = 0x86DD
PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1

DEDUP_WINDOW_US = 2       # mirrored copies share timestamps within ~1 us
DEDUP_MEMORY = 128        # recent frames remembered for duplicate detection


# ----------------------------------------------------------------------------
# Incremental statistics helper
# ----------------------------------------------------------------------------
class _Stat:
    """Running sum/sumsq/min/max accumulator (float64, O(1) memory)."""
    __slots__ = ("n", "s", "ss", "mn", "mx")

    def __init__(self) -> None:
        self.n = 0
        self.s = 0.0
        self.ss = 0.0
        self.mn = math.inf
        self.mx = -math.inf

    def add(self, x: float) -> None:
        self.n += 1
        self.s += x
        self.ss += x * x
        if x < self.mn:
            self.mn = x
        if x > self.mx:
            self.mx = x

    def get(self) -> tuple[float, float, float, float]:
        """Return (mean, std, max, min); std=0.0 for n<=1."""
        if self.n == 0:
            return 0.0, 0.0, 0.0, 0.0
        mean = self.s / self.n
        var = max(self.ss - self.s * mean, 0.0)
        std = math.sqrt(var / (self.n - 1)) if self.n > 1 else 0.0
        return mean, std, self.mx, self.mn


# ----------------------------------------------------------------------------
# Flow accumulator
# ----------------------------------------------------------------------------
class Flow:
    __slots__ = (
        "proto", "fwd_key", "start", "last", "last_fwd", "last_bwd",
        "fwd_n", "bwd_n", "fwd_bytes", "bwd_bytes",
        "fwd_len", "bwd_len", "all_len",
        "all_iat", "fwd_iat", "bwd_iat",
        "fwd_psh", "bwd_psh", "fwd_urg", "bwd_urg",
        "fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr",
        "fwd_hdr", "bwd_hdr", "init_fwd_win", "init_bwd_win",
        "fwd_win", "bwd_win", "fwd_data", "bwd_data",
        "active", "idle", "active_cur",
    )

    def __init__(self, proto: int, fwd_key: tuple, ts: float) -> None:
        self.proto = proto
        self.fwd_key = fwd_key
        self.start = ts
        self.last = ts
        self.last_fwd = ts
        self.last_bwd = None
        self.fwd_n = 0
        self.bwd_n = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_len = _Stat()
        self.bwd_len = _Stat()
        self.all_len = _Stat()
        self.all_iat = _Stat()
        self.fwd_iat = _Stat()
        self.bwd_iat = _Stat()
        self.fwd_psh = 0
        self.bwd_psh = 0
        self.fwd_urg = 0
        self.bwd_urg = 0
        self.fin = self.syn = self.rst = self.psh = 0
        self.ack = self.urg = self.ece = self.cwr = 0
        self.fwd_hdr = 0
        self.bwd_hdr = 0
        self.init_fwd_win = 0
        self.init_bwd_win = 0
        self.fwd_win = _Stat()
        self.bwd_win = _Stat()
        self.fwd_data = 0
        self.bwd_data = 0
        self.active = _Stat()
        self.idle = _Stat()
        self.active_cur = 0.0


def _safe_ratio(num: float, den: float) -> float:
    return num / den if den > 0 else 0.0


def flow_to_row(fl: Flow, cols: dict[str, list]) -> None:
    dur = fl.last - fl.start
    f_len = fl.fwd_len.get()
    b_len = fl.bwd_len.get()
    a_len = fl.all_len.get()
    if fl.active_cur > 0:
        fl.active.add(fl.active_cur)
        fl.active_cur = 0.0
    act = fl.active.get()
    idle = fl.idle.get()
    all_iat = fl.all_iat.get()
    fwd_iat = fl.fwd_iat.get()
    bwd_iat = fl.bwd_iat.get()

    vals = {
        "protocol": float(fl.proto),
        "flow_duration_s": dur,
        "fwd_packets": float(fl.fwd_n),
        "bwd_packets": float(fl.bwd_n),
        "fwd_bytes": float(fl.fwd_bytes),
        "bwd_bytes": float(fl.bwd_bytes),
        "fwd_len_max": f_len[2], "fwd_len_min": f_len[3],
        "fwd_len_mean": f_len[0], "fwd_len_std": f_len[1],
        "bwd_len_max": b_len[2], "bwd_len_min": b_len[3],
        "bwd_len_mean": b_len[0], "bwd_len_std": b_len[1],
        "pkt_len_max": a_len[2], "pkt_len_min": a_len[3],
        "pkt_len_mean": a_len[0], "pkt_len_std": a_len[1],
        "flow_iat_mean": all_iat[0], "flow_iat_std": all_iat[1],
        "flow_iat_max": all_iat[2], "flow_iat_min": all_iat[3],
        "fwd_iat_total": (fl.last_fwd - fl.start) if fl.fwd_iat.n > 0 else 0.0,
        "fwd_iat_mean": fwd_iat[0], "fwd_iat_std": fwd_iat[1],
        "fwd_iat_max": fwd_iat[2], "fwd_iat_min": fwd_iat[3],
        "bwd_iat_total": (fl.last_bwd - fl.start) if fl.bwd_iat.n > 0 else 0.0,
        "bwd_iat_mean": bwd_iat[0], "bwd_iat_std": bwd_iat[1],
        "bwd_iat_max": bwd_iat[2], "bwd_iat_min": bwd_iat[3],
        "fwd_psh": float(fl.fwd_psh), "bwd_psh": float(fl.bwd_psh),
        "fwd_urg": float(fl.fwd_urg), "bwd_urg": float(fl.bwd_urg),
        "fin_count": float(fl.fin), "syn_count": float(fl.syn),
        "rst_count": float(fl.rst), "psh_count": float(fl.psh),
        "ack_count": float(fl.ack), "urg_count": float(fl.urg),
        "ece_count": float(fl.ece), "cwr_count": float(fl.cwr),
        "fwd_header_bytes": float(fl.fwd_hdr), "bwd_header_bytes": float(fl.bwd_hdr),
        "down_up_ratio": _safe_ratio(fl.bwd_n, fl.fwd_n),
        "avg_pkt_size": _safe_ratio(fl.fwd_bytes + fl.bwd_bytes, fl.fwd_n + fl.bwd_n),
        "avg_fwd_seg": _safe_ratio(fl.fwd_bytes, fl.fwd_n),
        "avg_bwd_seg": _safe_ratio(fl.bwd_bytes, fl.bwd_n),
        "init_fwd_win": float(fl.init_fwd_win), "init_bwd_win": float(fl.init_bwd_win),
        "fwd_data_pkts": float(fl.fwd_data), "bwd_data_pkts": float(fl.bwd_data),
        "active_mean": act[0], "active_std": act[1], "active_max": act[2], "active_min": act[3],
        "idle_mean": idle[0], "idle_std": idle[1], "idle_max": idle[2], "idle_min": idle[3],
        "flow_bytes_s": _safe_ratio(fl.fwd_bytes + fl.bwd_bytes, dur),
        "flow_packets_s": _safe_ratio(fl.fwd_n + fl.bwd_n, dur),
        "fwd_win_mean": fl.fwd_win.get()[0] if fl.fwd_win.n else 0.0,
        "bwd_win_mean": fl.bwd_win.get()[0] if fl.bwd_win.n else 0.0,
    }
    for name in FEATURE_NAMES:
        v = vals[name]
        if not math.isfinite(v):
            v = 0.0  # NaN/inf guard: explicitly sanitised, never silently kept
        cols[name].append(v)


# ----------------------------------------------------------------------------
# Per-capture worker
# ----------------------------------------------------------------------------
def process_capture(args: dict) -> dict:
    """Stream one pcap -> flow table -> parquet. Returns run statistics."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    import psutil

    path = Path(args["path"])
    out_path = Path(args["out_path"])
    family = args["family"]
    binary = args["binary_label"]
    flow_timeout = float(args["flow_timeout_sec"])
    activity_cap = float(args["activity_timeout_sec"])
    max_pkts_flow = int(args["max_packets_per_flow"])

    cols: dict[str, list] = {n: [] for n in FEATURE_NAMES}
    meta: dict[str, list] = {c: [] for c in META_COLUMNS}
    flows: dict[tuple, Flow] = {}
    writer = None  # pq.ParquetWriter, created lazily on first flush

    stats = {
        "path": str(path), "packets": 0, "parsed": 0, "non_ip": 0,
        "malformed": 0, "nonfirst_frag": 0, "vlan_frames": 0,
        "duplicates": 0, "flows": 0, "sweeps": 0, "peak_rss_mb": 0.0,
        "error": None,
    }
    recent: deque = deque(maxlen=DEDUP_MEMORY)  # (ts_us, identity tuple)

    def flush() -> None:
        """Convert buffered flow rows to one parquet row-group (bounded memory)."""
        nonlocal writer
        if not meta["flow_id"]:
            return
        arrays = {n: np.array(cols[n], dtype=np.float32) for n in FEATURE_NAMES}
        for c in META_COLUMNS:
            arrays[c] = meta[c]
        table = pa.table(arrays)
        if writer is None:
            writer = pq.ParquetWriter(out_path, table.schema, compression="zstd")
        writer.write_table(table)
        for n in FEATURE_NAMES:
            cols[n].clear()
        for c in META_COLUMNS:
            meta[c].clear()

    def emit(fl: Flow, key: tuple, ended_by: str) -> None:
        flow_to_row(fl, cols)
        proto, src_b, sport, dst_b, dport = key
        try:
            src = socket.inet_ntoa(src_b) if len(src_b) == 4 else socket.inet_ntop(socket.AF_INET6, src_b)
            dst = socket.inet_ntoa(dst_b) if len(dst_b) == 4 else socket.inet_ntop(socket.AF_INET6, dst_b)
        except (OSError, ValueError):
            src, dst = repr(src_b), repr(dst_b)
        meta["capture_file"].append(path.name)
        meta["flow_id"].append(f"{proto}|{src}|{sport}|{dst}|{dport}")
        meta["family"].append(family)
        meta["binary_label"].append(binary)
        meta["src_ip"].append(src)
        meta["dst_ip"].append(dst)
        meta["src_port"].append(int(sport))
        meta["dst_port"].append(int(dport))
        meta["start_ts"].append(fl.start)
        meta["end_ts"].append(fl.last)
        meta["n_packets"].append(fl.fwd_n + fl.bwd_n)
        meta["ended_by"].append(ended_by)
        stats["flows"] += 1
        if stats["flows"] % FLUSH_ROWS == 0:
            flush()

    def sweep(now: float, force_small_first: bool = False) -> None:
        """Flush flows idle longer than the timeout (or smallest first if forced)."""
        dead = [k for k, fl in flows.items() if now - fl.last >= flow_timeout]
        for k in dead:
            emit(flows.pop(k), k, "timeout")
        if force_small_first and len(flows) > MAX_TRACKED:
            # Spoofed floods create huge numbers of single-packet flows that
            # will never age out within a short capture; flush them first.
            small = [k for k, fl in flows.items() if fl.fwd_n + fl.bwd_n <= 2]
            for k in small:
                emit(flows.pop(k), k, "sweep_forced")
            if len(flows) > MAX_TRACKED:
                old = sorted(flows.items(), key=lambda kv: kv[1].last)[:MAX_TRACKED // 2]
                for k, fl in old:
                    emit(flows.pop(k), k, "sweep_forced")

    t0 = time.perf_counter()
    first_ts = last_ts = None
    with open(path, "rb") as f:
        head = f.read(24)
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            stats["error"] = "pcapng not supported by flow meter (dataset is classic pcap)"
            return stats
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
                if incl > (1 << 31):  # fatal corruption guard (parity with audit parser)
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
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                if n_pkts % SWEEP_EVERY == 0:
                    stats["sweeps"] += 1
                    sweep(ts, force_small_first=True)

                # ---------------- link + network layer dissection ----------------
                try:
                    if len(frame) < 14:
                        raise ValueError("short ethernet frame")
                    etype = (frame[12] << 8) | frame[13]
                    off = 14
                    while etype == ETH_P_8021Q:  # explicit VLAN / QinQ unwrap
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
                    if frag_bits & 0x1FFF:  # non-first fragment: no L4 header
                        stats["nonfirst_frag"] += 1
                        continue
                    src_b, dst_b = l3[12:16], l3[16:20]
                except Exception:
                    stats["malformed"] += 1
                    continue

                # ---------------- transport layer dissection --------------------
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
                    l4_hdr = 8  # ICMP type/code/rest counted as L4 header
                payload_len = max(ip_total - ip_hdr - l4_hdr, 0)

                # ---------------- mirrored-duplicate detection ------------------
                # These captures contain the same frame multiple times (plain +
                # 802.1Q-tagged mirror copies, occasionally doubled plain copies).
                # Keep the FIRST copy; drop later copies within the timestamp window.
                if proto == PROTO_TCP:
                    ident = bytes(l3[ip_hdr + 4:ip_hdr + 12])  # seq+ack
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

                # ---------------- flow update -----------------------------------
                fwd_key = (proto, src_b, sport, dst_b, dport)
                bwd_key = (proto, dst_b, dport, src_b, sport)
                fl = flows.get(fwd_key)
                is_fwd = True
                if fl is None:
                    fl = flows.get(bwd_key)
                    if fl is not None:
                        is_fwd = False
                if fl is None:
                    fl = Flow(proto, fwd_key, ts)
                    flows[fwd_key] = fl
                    if proto == PROTO_TCP:
                        fl.init_fwd_win = win

                if fl.fwd_n + fl.bwd_n > 0:
                    d_all = ts - fl.last
                    fl.all_iat.add(d_all)
                    if d_all > IDLE_GAP_S:
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
                stats["parsed"] += 1

                if fl.fwd_n + fl.bwd_n >= max_pkts_flow:
                    emit(flows.pop(fl.fwd_key), fl.fwd_key, "packet_cap")
                elif ts - fl.start >= activity_cap:
                    emit(flows.pop(fl.fwd_key), fl.fwd_key, "activity_cap")

                if stats["packets"] % 100_000 == 0:
                    stats["peak_rss_mb"] = max(
                        stats["peak_rss_mb"], psutil.Process().memory_info().rss / (1 << 20))
            buf = buf[i:]

    # final sweep with the capture's end time, then emit + flush the rest
    end_ts = last_ts if last_ts is not None else time.time()
    sweep(end_ts, force_small_first=True)
    for key in list(flows.keys()):
        fl = flows.pop(key)
        dur = fl.last - fl.start
        ended = "capture_end" if dur < flow_timeout else "timeout"
        emit(fl, key, ended)
    flush()
    if writer is not None:
        writer.close()

    stats["elapsed_s"] = round(time.perf_counter() - t0, 2)
    stats["first_ts"] = first_ts
    stats["last_ts"] = last_ts
    stats["pkts_per_s"] = round(stats["packets"] / max(stats["elapsed_s"], 1e-9))
    return stats


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
PILOT_FILES = [
    "httperf_1st.pcap",          # benign (HTTP workload)
    "slow header_1st.pcap",      # application slow-rate attack
    "tcp syn flood.pcap",        # transport flood (spoofed SYN)
    "http flood get_1st.pcap",   # application high-rate flood
    "udp flood same port.pcap",  # transport flood (UDP)
]


def main() -> None:
    ap = argparse.ArgumentParser(description="DDoS-AT-2022 flow extraction")
    g = ap.add_mutually_exclusive_group(required=False)
    g.add_argument("--pilot", action="store_true", help="extract 5 representative captures")
    g.add_argument("--all", action="store_true", help="extract every capture")
    g.add_argument("--files", nargs="+", metavar="SUBSTR", help="captures matching all substrings")
    ap.add_argument("--families", nargs="+", default=None, metavar="FAM",
                    help="restrict to these attack families (from audit taxonomy)")
    ap.add_argument("--invert", action="store_true",
                    help="invert the family filter (extract everything else)")
    ap.add_argument("--out", default=None, help="output subdir under data/processed (default: per mode)")
    args = ap.parse_args()

    cfg = load_config()
    entries = [e for e in discover_files(cfg.dataset_path) if e["extension"] == ".pcap"]
    if args.families:
        fams = {f.lower() for f in args.families}
        entries = [e for e in entries
                   if (e["family"].lower() in fams) != bool(args.invert)]
    if args.pilot:
        chosen = [e for e in entries if e["filename"] in PILOT_FILES]
        out_sub = args.out or "_pilot"
    elif args.all or args.families:
        chosen = entries
        out_sub = args.out or "flows"
    elif args.files:
        chosen = [e for e in entries if all(s.lower() in e["filename"].lower() for s in args.files)]
        out_sub = args.out or "flows"
    else:
        ap.error("one of --pilot, --all, --files, --families is required")
        return
    if not chosen:
        log.error("No captures matched. Check names/filters.")
        sys.exit(2)

    out_dir = cfg.processed_dir / out_sub
    out_dir.mkdir(parents=True, exist_ok=True)
    jobs = [{
        "path": e["path"], "family": e["family"], "binary_label": e["binary_label"],
        "out_path": str(out_dir / f"{Path(e['filename']).stem}.parquet"),
        "flow_timeout_sec": cfg.flow_timeout_sec,
        "activity_timeout_sec": cfg.activity_timeout_sec,
        "max_packets_per_flow": cfg.max_packets_per_flow,
    } for e in chosen]

    with timed_stage(1, 3, f"Extracting flows from {len(jobs)} captures"):
        workers = max(1, min(len(jobs), os.cpu_count() or 1, 6))
        log.info("using %d worker processes", workers)
        results = []
        if workers == 1:
            results = [process_capture(j) for j in jobs]
        else:
            with ProcessPoolExecutor(max_workers=workers) as ex:
                for r in ex.map(process_capture, jobs):
                    results.append(r)
                    log.info(
                        "  %-40s %9s pkts | %8s flows | %7.1fs | %6.0fk pkt/s | "
                        "rss<=%dMB | vlan=%d dup=%d non_ip=%d malformed=%d frag=%d",
                        Path(r["path"]).name, f"{r['packets']:,}", f"{r['flows']:,}",
                        r.get("elapsed_s", 0), r.get("pkts_per_s", 0) / 1e3,
                        r.get("peak_rss_mb", 0), r.get("vlan_frames", 0),
                        r.get("duplicates", 0), r.get("non_ip", 0),
                        r.get("malformed", 0), r.get("nonfirst_frag", 0))

    with timed_stage(2, 3, "Writing schema + summary"):
        schema_doc = {
            "feature_columns": [{"name": n, "description": d} for n, d in FEATURES],
            "metadata_columns": META_COLUMNS,
            "leakage_policy": "IPs, ports, timestamps, capture identity are metadata only; never features.",
            "constants": {"idle_gap_s": IDLE_GAP_S, "flow_timeout_s": cfg.flow_timeout_sec,
                          "activity_timeout_s": cfg.activity_timeout_sec,
                          "max_packets_per_flow": cfg.max_packets_per_flow,
                          "dedup_window_us": DEDUP_WINDOW_US,
                          "dedup_memory": DEDUP_MEMORY},
        }
        schema_path = cfg.processed_dir / "flow_schema.json"
        schema_path.write_text(json.dumps(schema_doc, indent=2), encoding="utf-8")

        tot_pkts = sum(r["packets"] for r in results)
        tot_flows = sum(r["flows"] for r in results)
        tot_dups = sum(r.get("duplicates", 0) for r in results)
        errs = [r for r in results if r.get("error")]
        log.info("extraction totals: %s packets -> %s duplicates removed -> %s unique packets -> %s flows; errors: %d",
                 f"{tot_pkts:,}", f"{tot_dups:,}", f"{tot_pkts - tot_dups:,}", f"{tot_flows:,}", len(errs))

    with timed_stage(3, 3, "Verifying parquet outputs"):
        import pyarrow.parquet as pq
        for r in results:
            src = Path(r["path"])
            if r.get("error"):
                log.warning("  %s -> ERROR: %s", src.name, r["error"])
                continue
            parquet_path = out_dir / f"{src.stem}.parquet"
            md = pq.read_metadata(parquet_path)
            log.info("  %-40s %8d flow rows | %.1f MB parquet",
                     src.name, md.num_rows, parquet_path.stat().st_size / (1 << 20))
    log.info("flow schema written to %s", schema_path)


if __name__ == "__main__":
    main()
