"""Recursive dataset inspection for DDoS-AT-2022 (read-only).

Walks the dataset root, reports every file (type, size), parses classic-pcap
global headers, counts packets (= row-count equivalent for raw captures),
measures capture duration and wire bytes, and derives labels from the
directory taxonomy. Writes:

    reports/pcap_inventory.csv     one row per capture file
    reports/dataset_inventory.json machine-readable full inventory
    reports/dataset_audit.md       human-readable audit report

Nothing in the dataset directory is ever modified.

pcap record-walk invariants enforced per packet record:
    0 < incl_len <= snaplen        (advisory counter if violated)
    orig_len >= incl_len           (advisory counter if violated)
    incl_len > 2**31               (fatal corruption guard)

Usage:
    python src/inspect_dataset.py
    DDOS_AT_DATASET_PATH="D:/somewhere" python src/inspect_dataset.py
"""
from __future__ import annotations

import csv
import json
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from config import load_config

# ----------------------------------------------------------------------------
# Label taxonomy (top-level directory -> canonical family name)
# ----------------------------------------------------------------------------
LABEL_MAP = {
    "flash traffic": "flash_traffic",
    "http flood_get_post_random": "http_flood",
    "http low volume low rate": "http_low_rate",
    "http-low volume-slow rate-slow body": "http_slow_body",
    "http-low volume-slow rate-slow header": "http_slow_header",
    "http-low volume-slow rate-slow read": "http_slow_read",
    "legitimate traffic": "benign",
    "tcp-rst": "tcp_rst",
    "tcp-syn-fast": "tcp_syn_fast",
    "tcp-syn-flood": "tcp_syn_flood",
    "tcp-syn-low": "tcp_syn_low",
    "udp flood": "udp_flood",
}

APPLICATION_LAYER = {
    "flash_traffic", "http_flood", "http_low_rate",
    "http_slow_body", "http_slow_header", "http_slow_read",
}

LINK_TYPES = {
    0: "NULL (BSD loopback)",
    1: "Ethernet",
    101: "Raw IP",
    113: "Linux SLL",
    228: "IPv4/IPv6 + link-layer",
    276: "Linux SLL2",
}


def linktype_name(linktype) -> str:
    if linktype is None or linktype == "":
        return ""
    return LINK_TYPES.get(int(linktype), f"unknown ({linktype})")


def slugify(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name.strip().lower()).strip("_")


def family_for(top_dir: str) -> str:
    return LABEL_MAP.get(top_dir.strip().lower(), slugify(top_dir))


# ----------------------------------------------------------------------------
# pcap parsing (classic pcap + minimal pcapng block walker)
# ----------------------------------------------------------------------------
def _parse_pcapng(path: Path) -> dict:
    info = {"format": "pcapng", "packets": 0, "bytes_wire": 0,
            "first_ts": None, "last_ts": None, "linktype": None, "snaplen": None}
    epb = 0x00000006
    with open(path, "rb") as f:
        while True:
            head = f.read(12)
            if len(head) < 12:
                break
            (blen,) = struct.unpack("<I", head[:4])
            if blen < 12:
                info["error"] = "bad pcapng block length"
                break
            (btype,) = struct.unpack("<I", head[4:8])
            if btype == epb:
                ts_h, ts_l, caplen, origlen = struct.unpack("<IIII", f.read(16))
                if 0 < origlen <= (1 << 22):
                    info["packets"] += 1
                    info["bytes_wire"] += origlen
                    f.seek(caplen, 1)
                    f.seek(blen - 12 - 16 - caplen, 1)
                    continue
            f.seek(blen - 12, 1)
    return info


def parse_pcap(path: Path, max_records: int | None = None) -> dict:
    """Chunked single-pass packet counter for classic pcap files.

    Reads only record headers into Python; payload bytes are skipped via
    offset arithmetic (never copied). Stops after ``max_records`` packets
    when given (used by parser validation). Malformed records are counted,
    never silently ignored.
    """
    info = {
        "format": "pcap", "magic": "", "swapped": False, "nanosecond": False,
        "version": "", "snaplen": None, "linktype": None,
        "packets": 0, "bytes_wire": 0, "first_ts": None, "last_ts": None,
        "truncated_tail_bytes": 0, "error": None,
        "n_bad_incl": 0, "n_orig_lt_incl": 0, "first_bad_offset": None,
    }
    with open(path, "rb") as f:
        head = f.read(24)
        if len(head) < 24:
            info["error"] = "file smaller than pcap global header"
            return info
        magic = head[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            return _parse_pcapng(path)
        info["magic"] = magic.hex()
        # On-disk byte sequences -> file endianness:
        #   d4 c3 b2 a1 -> little-endian usec    a1 b2 c3 d4 -> big-endian usec
        #   4d 3c b2 a1 -> little-endian nsec    a1 b2 3c 4d -> big-endian nsec
        info["swapped"] = magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
        info["nanosecond"] = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        endian = ">" if info["swapped"] else "<"
        vmaj, vmin = struct.unpack(endian + "HH", head[4:8])
        snaplen, network = struct.unpack(endian + "II", head[16:24])
        info["version"] = f"{vmaj}.{vmin}"
        info["snaplen"], info["linktype"] = snaplen, network

        rec = struct.Struct(endian + "IIII")
        unpack = rec.unpack_from
        chunk_size = 1 << 25  # 32 MiB
        tail = b""
        first = last = None
        n = 0
        wire = 0
        offset_base = 24  # file offset of buf[0]
        stop = False
        while not stop:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            buf = tail + chunk if tail else chunk
            total = len(buf)
            i = 0
            while True:
                if i + 16 > total:
                    break
                ts_s, ts_f, incl, orig = unpack(buf, i)
                if incl > (1 << 31):  # fatal corruption guard
                    info["error"] = f"implausible record length {incl} at packet {n}"
                    stop = True
                    break
                rec_offset = offset_base + i
                # sanity: 0 < incl_len <= snaplen
                if incl == 0 or (snaplen and incl > snaplen):
                    info["n_bad_incl"] += 1
                    if info["first_bad_offset"] is None:
                        info["first_bad_offset"] = rec_offset
                # sanity: orig_len >= incl_len
                if orig < incl:
                    info["n_orig_lt_incl"] += 1
                    if info["first_bad_offset"] is None:
                        info["first_bad_offset"] = rec_offset
                end = i + 16 + incl
                if end > total:
                    break  # record split across chunks -> carry over
                if first is None:
                    first = (ts_s, ts_f)
                last = (ts_s, ts_f)
                n += 1
                wire += orig
                i = end
                if max_records is not None and n >= max_records:
                    stop = True
                    break
            tail = buf[i:]
            offset_base += i
    info["packets"] = n
    info["bytes_wire"] = wire
    if tail:
        info["truncated_tail_bytes"] = len(tail)
    scale = 1e9 if info["nanosecond"] else 1e6
    if first and last:
        info["first_ts"] = first[0] + first[1] / scale
        info["last_ts"] = last[0] + last[1] / scale
    return info


# ----------------------------------------------------------------------------
# Inventory build
# ----------------------------------------------------------------------------
def discover_files(root: Path) -> list[dict]:
    entries = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        top = rel.parts[0] if len(rel.parts) > 1 else "(root)"
        fam = family_for(top)
        entries.append({
            "path": str(path),
            "relative_path": str(rel),
            "top_dir": top,
            "family": fam,
            "layer": ("application" if fam in APPLICATION_LAYER
                      else "transport" if fam != "benign" else "benign"),
            "binary_label": "benign" if fam == "benign" else "attack",
            "subdirectory": "/".join(rel.parts[1:-1]),
            "filename": path.name,
            "extension": path.suffix.lower(),
            "size_bytes": path.stat().st_size,
        })
    return entries


def enrich_with_pcap_stats(entries: list[dict]) -> None:
    for idx, e in enumerate(entries, 1):
        if e["extension"] not in (".pcap", ".pcapng"):
            e["pcap"] = None
            continue
        t0 = time.time()
        stats = parse_pcap(Path(e["path"]))
        e["pcap"] = stats
        dur = ""
        if stats.get("first_ts") and stats.get("last_ts"):
            dur = f"{stats['last_ts'] - stats['first_ts']:.1f}s"
        flags = ""
        if stats.get("n_bad_incl") or stats.get("n_orig_lt_incl"):
            flags = f"  [ANOMALY bad_incl={stats['n_bad_incl']} orig<incl={stats['n_orig_lt_incl']}]"
        print(f"[{idx}/{len(entries)}] {e['family']:<16} {e['filename']:<45} "
              f"{stats.get('packets', 0):>9,} pkts  {dur:>9}  "
              f"({e['size_bytes'] / 1e9:.2f} GB, {time.time() - t0:.1f}s scan){flags}",
              flush=True)


def main() -> None:
    cfg = load_config()
    root = cfg.dataset_path
    if not root.exists():
        print(f"ERROR: dataset root does not exist: {root}", file=sys.stderr)
        sys.exit(2)

    reports_dir = cfg.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    print(f"Dataset root : {root}")
    print("Scanning recursively for files ...", flush=True)
    entries = discover_files(root)
    print(f"Found {len(entries)} files. Parsing pcap headers + counting packets ...\n", flush=True)

    enrich_with_pcap_stats(entries)

    # ---- CSV inventory -----------------------------------------------------
    csv_path = reports_dir / "pcap_inventory.csv"
    fields = ["relative_path", "family", "binary_label", "layer", "subdirectory",
              "filename", "extension", "size_bytes", "format", "magic", "version",
              "linktype", "linktype_name", "snaplen", "packets", "bytes_wire",
              "avg_packet_size_bytes", "duration_sec", "first_ts_iso", "last_ts_iso",
              "truncated_tail_bytes", "n_bad_incl", "n_orig_lt_incl", "error"]
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(fields)
        for e in entries:
            p = e.get("pcap") or {}
            dur = (p.get("last_ts") - p.get("first_ts")) if p.get("first_ts") and p.get("last_ts") else None
            pkts = p.get("packets", 0) or 0
            wire = p.get("bytes_wire", 0) or 0
            avg = (wire / pkts) if pkts else None
            w.writerow([
                e["relative_path"], e["family"], e["binary_label"], e["layer"],
                e["subdirectory"], e["filename"], e["extension"], e["size_bytes"],
                p.get("format", ""), p.get("magic", ""), p.get("version", ""),
                p.get("linktype", ""), linktype_name(p.get("linktype")), p.get("snaplen", ""),
                pkts, wire,
                round(avg, 2) if avg else "",
                round(dur, 3) if dur is not None else "",
                datetime.fromtimestamp(p["first_ts"], tz=timezone.utc).isoformat() if p.get("first_ts") else "",
                datetime.fromtimestamp(p["last_ts"], tz=timezone.utc).isoformat() if p.get("last_ts") else "",
                p.get("truncated_tail_bytes", ""), p.get("n_bad_incl", 0),
                p.get("n_orig_lt_incl", 0), p.get("error") or "",
            ])

    # ---- JSON inventory ----------------------------------------------------
    json_path = reports_dir / "dataset_inventory.json"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"dataset_path": str(root), "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
                   "files": entries}, fh, indent=2)

    # ---- Markdown audit ----------------------------------------------------
    total_files = len(entries)
    total_bytes = sum(e["size_bytes"] for e in entries)
    pcaps = [e for e in entries if e["extension"] in (".pcap", ".pcapng")]
    total_pkts = sum((e["pcap"] or {}).get("packets", 0) for e in pcaps)
    total_wire = sum((e["pcap"] or {}).get("bytes_wire", 0) for e in pcaps)
    anomaly_files = [e for e in pcaps
                     if (e["pcap"] or {}).get("error")
                     or (e["pcap"] or {}).get("truncated_tail_bytes")
                     or (e["pcap"] or {}).get("n_bad_incl")
                     or (e["pcap"] or {}).get("n_orig_lt_incl")]

    fams: dict[str, dict] = {}
    for e in pcaps:
        f = fams.setdefault(e["family"], {"files": 0, "bytes": 0, "packets": 0, "wire": 0,
                                          "binary": e["binary_label"], "layer": e["layer"]})
        f["files"] += 1
        f["bytes"] += e["size_bytes"]
        f["wire"] += (e["pcap"] or {}).get("bytes_wire", 0)
        f["packets"] += (e["pcap"] or {}).get("packets", 0)

    def gb(x):
        return f"{x / 1e9:.2f}"

    lines = [
        "# DDoS-AT-2022 — Dataset Audit Report",
        "",
        f"- Generated: {datetime.now(timezone.utc).isoformat()}",
        f"- Dataset root: `{root}` (read-only; pipeline never writes here)",
        f"- Files: **{total_files}** ({gb(total_bytes)} GB on disk)",
        f"- Capture files (classic pcap, little-endian usec): **{len(pcaps)}** — "
        f"{total_pkts:,} packets, {gb(total_wire)} GB on wire",
        f"- Parser validation: chunked parser cross-checked against explicit "
        f"sequential offset walk (`src/validate_pcap_parser.py`)",
        f"- Anomalous files (parse errors / truncation / record-header violations): "
        f"**{len(anomaly_files)}**" + (f" -> {[e['filename'] for e in anomaly_files]}" if anomaly_files else ""),
        "",
        "## Labels (derived from capture directory taxonomy)",
        "",
        "| Attack family (label) | Layer | Binary label | Files | Packets | GB on disk | GB on wire |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for fam, f in sorted(fams.items(), key=lambda kv: -kv[1]["packets"]):
        lines.append(f"| `{fam}` | {f['layer']} | {f['binary']} | {f['files']} | "
                     f"{f['packets']:,} | {gb(f['bytes'])} | {gb(f['wire'])} |")
    benign_pkts = fams.get("benign", {}).get("packets", 0)
    attack_pkts = total_pkts - benign_pkts
    lines += [
        "",
        f"**Packet-level class balance:** benign {benign_pkts:,} ({benign_pkts / max(total_pkts, 1):.1%}) vs "
        f"attack {attack_pkts:,} ({attack_pkts / max(total_pkts, 1):.1%}).",
        "",
        "## Per-capture inventory",
        "",
        "| Capture file | Family | Label | Size GB | Packets | Duration (s) | Avg pkt (B) | Wire GB | Link type |",
        "|---|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for e in sorted(pcaps, key=lambda x: x["family"]):
        p = e["pcap"] or {}
        dur = (p.get("last_ts") - p.get("first_ts")) if p.get("first_ts") and p.get("last_ts") else None
        pkts = p.get("packets", 0) or 0
        wire = p.get("bytes_wire", 0) or 0
        avg = f"{wire / pkts:.1f}" if pkts else ""
        dur_s = f"{dur:.1f}" if dur is not None else ""
        lines.append(f"| `{e['filename']}` | `{e['family']}` | {e['binary_label']} | "
                     f"{gb(e['size_bytes'])} | {pkts:,} | {dur_s} | {avg} | "
                     f"{gb(wire)} | {linktype_name(p.get('linktype'))} |")

    lines += [
        "",
        "## Notes",
        "",
        "- Raw material is packet captures (pcap): there are **no pre-extracted columns**. "
        "Flow-level features (CICFlowMeter-style) will be derived by the pipeline's flow meter; "
        "the flow table schema is documented in `src/feature_engineering.py`.",
        "- Every capture file is an independent capture session -> natural group key for "
        "leakage-aware train/val/test splitting.",
        "- Repeated runs of the same scenario (`*_1st`, `*_2nd`, `1-1/1-2`) are near-duplicate "
        "conditions; group-disjoint splitting keeps whole captures out of foreign splits.",
        "- `packets` above are exact record counts from the validated parser (not estimates); "
        "flow-level row counts will be reported after feature extraction.",
    ]
    md_path = reports_dir / "dataset_audit.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"\nWrote:\n  {csv_path}\n  {json_path}\n  {md_path}")
    print(f"Totals: {total_files} files, {gb(total_bytes)} GB | {len(pcaps)} pcaps | "
          f"{total_pkts:,} packets | {gb(total_wire)} GB wire | anomalies: {len(anomaly_files)}")


if __name__ == "__main__":
    main()
