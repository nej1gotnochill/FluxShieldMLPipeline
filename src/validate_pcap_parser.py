"""Byte-exact validation of the classic-pcap record parser.

Validates src/inspect_dataset.py::parse_pcap against the pcap specification
before any dataset-wide statistics are trusted.

Procedure
---------
1. Print the 24-byte global header field by field.
2. Walk the FIRST N packet records with explicit byte offsets and print
   (packet number, timestamp, captured length, original length, byte offset).
   The next record is read by an explicit seek to
       expected_next = offset + 16 + incl_len
   so the record-chain invariant is tested, not assumed.
3. Per-record sanity: 0 < incl_len <= snaplen and orig_len >= incl_len.
4. Full sequential walk of a small file; totals compared with the chunked
   production parser.
5. Prefix walk (first K records) of a large file; compared with
   parse_pcap(max_records=K).

Exit code 0 = all checks passed; 1 = validation failure.

Usage:
    python src/validate_pcap_parser.py [pcap_path]
"""
from __future__ import annotations

import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from config import load_config
from inspect_dataset import linktype_name, parse_pcap

# Global header for little-endian files: magic, vmaj, vmin, thiszone,
# sigfigs, snaplen, network
GLOBAL_LE = struct.Struct("<IHHiIII")
REC_LE = struct.Struct("<IIII")
EXPECTED_MAGIC = 0xA1B2C3D4


def ts_str(ts_s: int, ts_u: int) -> str:
    dt = datetime.fromtimestamp(ts_s, tz=timezone.utc)
    return f"{dt:%Y-%m-%d %H:%M:%S}.{ts_u:06d}"


def validate_global_header(path: Path) -> tuple[int, int] | None:
    """Print and verify the global header; return (snaplen, linktype)."""
    with open(path, "rb") as f:
        raw = f.read(24)
    if len(raw) < 24:
        print(f"  FAIL: file smaller than 24-byte global header ({len(raw)} bytes)")
        return None
    magic, vmaj, vmin, thiszone, sigfigs, snaplen, linktype = GLOBAL_LE.unpack(raw)
    print(f"  magic          : {raw[:4].hex(' ')}  (value 0x{magic:08X}, "
          f"expected 0x{EXPECTED_MAGIC:08X})")
    print(f"  version        : {vmaj}.{vmin} (expected 2.4)")
    print(f"  thiszone       : {thiszone}")
    print(f"  sigfigs        : {sigfigs}")
    print(f"  snaplen        : {snaplen:,} bytes")
    print(f"  network/link   : {linktype} ({linktype_name(linktype)})")
    ok = magic == EXPECTED_MAGIC
    print(f"  global header  : {'PASS' if ok else 'FAIL'}")
    return (snaplen, linktype) if ok else None


def walk_first_records(path: Path, snaplen: int, n: int = 10) -> bool:
    """Explicit offset-chain walk of the first N records."""
    print(f"\n[2/5] First {n} packet records with explicit offset chain "
          f"(invariant: next = offset + 16 + incl_len)")
    failures = 0
    with open(path, "rb") as f:
        size = path.stat().st_size
        offset = 24
        prev_next = None
        rows = []
        for k in range(n):
            if offset + 16 > size:
                print(f"  packet {k}: reached end of file after {k} records")
                break
            f.seek(offset)
            hdr = f.read(16)
            ts_s, ts_u, incl, orig = REC_LE.unpack(hdr)

            # --- sanity checks -------------------------------------------------
            checks = []
            if not (0 < incl <= (snaplen if snaplen else incl)):
                checks.append(f"FAIL incl_len {incl} vs snaplen {snaplen}")
            if orig < incl:
                checks.append(f"FAIL orig_len {orig} < incl_len {incl}")
            if prev_next is not None and offset != prev_next:
                checks.append(f"FAIL chain: offset {offset} != expected {prev_next}")

            rec_ts = ts_str(ts_s, ts_u)
            next_expected = offset + 16 + incl
            print(f"  packet {k:>2}: offset={offset:>10,}  ts={rec_ts}  "
                  f"incl_len={incl:>7,}  orig_len={orig:>7,}  "
                  f"next_offset={next_expected:>10,}"
                  + (f"   {'; '.join(checks)}" if checks else "  [sanity OK]"))
            failures += len(checks)

            # --- explicit jump: the next record MUST live at next_expected ----
            rows.append((k, offset, ts_s, ts_u, incl, orig, next_expected))
            prev_next = next_expected
            offset = next_expected

        # verify the record AFTER the printed prefix also parses cleanly
        # at the expected offset (proves the chain continues)
        k, offset, ts_s, ts_u, incl, orig, nxt = rows[-1]
        f.seek(nxt)
        hdr = f.read(16)
        if len(hdr) == 16:
            ts2_s, ts2_u, incl2, orig2 = REC_LE.unpack(hdr)
            ok = (incl2 > 0 and orig2 >= incl2 and ts2_s >= ts_s)
            print(f"  packet {k + 1:>2}: offset={nxt:>10,}  ts={ts_str(ts2_s, ts2_u)}  "
                  f"incl_len={incl2:>7,}  orig_len={orig2:>7,}  "
                  f"[chain continues {'OK' if ok else 'FAIL'}]")
            if not ok:
                failures += 1
    return failures == 0


def sequential_walk(path: Path, snaplen: int, stop_at: int | None = None) -> dict:
    """Independent record-at-a-time walk (seek per record)."""
    size = path.stat().st_size
    n = 0
    wire = 0
    violations = 0
    first = last = None
    offset = 24
    with open(path, "rb") as f:
        while offset + 16 <= size:
            f.seek(offset)
            ts_s, ts_u, incl, orig = REC_LE.unpack(f.read(16))
            if incl > (1 << 31):
                break
            if incl == 0 or (snaplen and incl > snaplen) or orig < incl:
                violations += 1
            if stop_at is not None and n >= stop_at:
                break
            n += 1
            wire += orig
            if first is None:
                first = (ts_s, ts_u)
            last = (ts_s, ts_u)
            offset += 16 + incl
    return {"packets": n, "bytes_wire": wire, "violations": violations,
            "end_offset": offset, "file_size": size,
            "first_ts": first, "last_ts": last,
            "exact_fit": offset == size}


def compare(seq: dict, chunked: dict, label: str) -> bool:
    ok = (seq["packets"] == chunked["packets"]
          and seq["bytes_wire"] == chunked["bytes_wire"])
    print(f"  [{label}] sequential: {seq['packets']:,} pkts / {seq['bytes_wire']:,} B wire | "
          f"chunked: {chunked['packets']:,} pkts / {chunked['bytes_wire']:,} B wire | "
          f"{'MATCH' if ok else 'MISMATCH'}"
          + ("" if seq["violations"] == 0 else f" | seq violations: {seq['violations']}"))
    return ok


def main() -> int:
    cfg = load_config()
    root = cfg.dataset_path
    pcaps = sorted(root.rglob("*.pcap"), key=lambda p: p.stat().st_size)
    if not pcaps:
        print(f"ERROR: no .pcap files under {root}", file=sys.stderr)
        return 2

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else pcaps[0]
    large = next((p for p in pcaps if p.stat().st_size > 1_000_000_000), None)
    medium = next((p for p in pcaps if 100_000_000 < p.stat().st_size <= 400_000_000), None)

    print("=" * 78)
    print("PCAP PARSER VALIDATION")
    print("=" * 78)
    print(f"\n[1/5] Global header of: {target}")
    print(f"      (smallest pcap in dataset, {target.stat().st_size:,} bytes)")
    gh = validate_global_header(target)
    if gh is None:
        return 1
    snaplen, _ = gh

    ok = True
    ok &= walk_first_records(target, snaplen, n=10)

    print("\n[3/5] Full sequential walk (independent) vs chunked production parser")
    seq = sequential_walk(target, snaplen)
    chunked = parse_pcap(target)
    print(f"      file size {seq['file_size']:,} B; walk ended at {seq['end_offset']:,} B; "
          f"exact_fit={seq['exact_fit']}")
    ok &= compare(seq, chunked, "small file")

    if medium is not None:
        print(f"\n[4/5] Medium-file cross-check: {medium.name} "
              f"({medium.stat().st_size / 1e6:.0f} MB)")
        seq = sequential_walk(medium, snaplen)
        chunked = parse_pcap(medium)
        ok &= compare(seq, chunked, "medium file")

    if large is not None:
        k = 500_000
        print(f"\n[5/5] Large-file prefix cross-check (first {k:,} records): {large.name} "
              f"({large.stat().st_size / 1e9:.2f} GB)")
        seq = sequential_walk(large, snaplen, stop_at=k)
        chunked = parse_pcap(large, max_records=k)
        ok &= compare(seq, chunked, "large prefix")

    print("\n" + "=" * 78)
    print("VALIDATION " + ("PASSED — parser is spec-compliant" if ok
                           else "FAILED — do not trust dataset statistics yet"))
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
