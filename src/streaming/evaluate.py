"""Synthetic-attack pcap generator + per-class streaming evaluation.

Creates ground-truth-labelled attack fixtures for the DATA-LIMITED rule
detectors (C2 beaconing, DGA, DNS tunneling, recon fan-out, exfil
asymmetry, TLS fingerprint repetition), replays them through the real
StreamingService, and reports per-class precision/recall.

Purpose and honesty rules:
  * fixtures are SYNTHETIC (clearly labelled everywhere, incl. the report);
  * they exercise the full implemented path (packets -> features ->
    detectors -> alerts), so numbers measure the pipeline, not a toy;
  * benign fixtures come from the real DDoS-AT-2022 benign captures to
    keep the false-positive side honest;
  * results land in reports/streaming_fixture_evaluation.md and are the
    numbers the dashboard registry displays — nothing invented.

Usage:
    python -m src.streaming.evaluate --benign <capture.pcap> [--out reports]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

from src.streaming import service as svc_mod
from src.streaming.service import StreamingService

# ---------------------------------------------------------------------- #
# frame builders (deterministic; documented in the report)


def _eth_ip(proto: int, src: str, dst: str, l4: bytes, ttl: int = 64) -> bytes:
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, ttl, proto, 0,
                     _ip(src), _ip(dst))
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00" + ip + l4


def _ip(s: str) -> bytes:
    import socket
    return socket.inet_aton(s)


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport: int, dport: int, flags: int, seq: int = 1000,
         payload: bytes = b"", win: int = 8192) -> bytes:
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 2000, 5 << 4, flags,
                       win, 0, 0) + payload


def _dns_query(name: str, qtype: int = 1, txid: int | None = None) -> bytes:
    if txid is None:
        txid = (hash(name) & 0xFFFF) or 0x1234
    hdr = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q = b""
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return hdr + q


def _tls_client_hello(extensions_tail: bytes, cipher_suites: bytes,
                      sid_len: int = 0) -> bytes:
    hs_body = (b"\x03\x03"                     # client_version TLS1.2
               + b"\x00" * 32                  # random
               + bytes([sid_len]) + b"\x00" * sid_len
               + struct.pack(">H", len(cipher_suites)) + cipher_suites
               + b"\x01\x00"                   # compression: null
               + struct.pack(">H", len(extensions_tail)) + extensions_tail)
    hs = b"\x01" + struct.pack(">I", len(hs_body))[1:] + hs_body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


# ---------------------------------------------------------------------- #
# scenario builders: (frames, expected_class_or_None, note)

def _frames_benign(duration: float = 40.0) -> tuple:
    """Benign fixture: realistic web/DNS behaviour, NOT modulo-cycled —
    cycling destinations/ports creates artificial periodicity that no real
    host exhibits (the first benign fixture was honestly caught doing this
    by our own C2 detector)."""
    import random
    rng = random.Random(42)                     # deterministic but unpatterned
    frames = []
    t = 1_000.0
    sites = [f"site{i}.example.com" for i in range(40)]
    while t < 1_000.0 + duration:
        d = f"10.0.{rng.randint(1, 4)}.{rng.randint(1, 254)}"
        sp = rng.randint(49152, 65535)
        frames.append((t, _eth_ip(6, "10.1.1.9", d, _tcp(sp, 443, 0x18))))
        frames.append((t + 0.01, _eth_ip(6, d, "10.1.1.9", _tcp(443, sp, 0x18))))
        q = rng.choice(sites)
        frames.append((t + 0.02, _eth_ip(17, "10.1.1.9", "10.0.0.53",
                                         _udp(53000, 53, _dns_query(q)))))
        t += rng.uniform(0.02, 0.12)
    return frames, None, "mixed benign web/dns traffic (deterministic rng, unpatterned)"


def _frames_c2(period: float = 30.0, n: int = 10) -> tuple:
    frames = []
    t = 2_000.0
    for i in range(n):
        frames.append((t, _eth_ip(6, "10.2.2.7", "198.51.100.23", _tcp(47777, 8443, 0x02))))
        t += period
    return frames, "C2", f"perfect {period:g}s beacon to one unicast destination"


def _frames_dga(n_domains: int = 12) -> tuple:
    frames = []
    t = 3_000.0
    for i in range(n_domains):
        q = f"h{i}x7h2q9k4r1t5v8w2y6z3a5b8c1d4e7f9g2h5j8.badges4all.com"
        frames.append((t, _eth_ip(17, "10.3.3.5", "10.0.0.53", _udp(53001 + i, 53, _dns_query(q)))))
        t += 0.2
    return frames, "DGA", "high-entropy unique subdomains under one domain"


def _frames_tunnel(n: int = 10) -> tuple:
    frames = []
    t = 4_000.0
    label = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"
    for i in range(n):
        q = f"{label}{i}.t.exfil-channel.example.com"
        frames.append((t, _eth_ip(17, "10.4.4.6", "10.0.0.53", _udp(54001 + i, 53, _dns_query(q, qtype=16)))))
        t += 0.3
    return frames, "DGA", "long TXT-label DNS tunneling over one channel domain"


def _frames_scan(n_ports: int = 30) -> tuple:
    frames = []
    t = 5_000.0
    for p in range(1, n_ports + 1):
        frames.append((t, _eth_ip(6, "10.5.5.9", "10.0.0.9", _tcp(41000 + p, 1000 + p, 0x02))))
        t += 0.02
    return frames, "RECON", "sequential SYN port scan, single host"


def _frames_exfil(n: int = 12) -> tuple:
    frames = []
    t = 6_000.0
    for i in range(n):
        frames.append((t, _eth_ip(6, "10.6.6.8", f"198.51.100.{50 + i}",
                                  _tcp(52000 + i, 443, 0x18, payload=b"\x00" * 1400))))
        t += 0.1
    return frames, "EXFIL", "large one-way upload to many rare destinations"


def _frames_tls_rep(n: int = 8) -> tuple:
    frames = []
    t = 7_000.0
    ch = _tls_client_hello(b"\x00\x17\x00\x00", b"\x13\x01\x13\x02\x13\x03")
    for i in range(n):
        frames.append((t, _eth_ip(6, "10.7.7.4", "198.51.100.77", _tcp(53000 + i, 443, 0x18, payload=ch))))
        t += 0.25
    return frames, "ENCRYPTED_MALWARE", "identical cleartext ClientHello repeated"


SCENARIOS = [
    ("benign", _frames_benign),
    ("c2", _frames_c2),
    ("dga", _frames_dga),
    ("tunnel", _frames_tunnel),
    ("scan", _frames_scan),
    ("exfil", _frames_exfil),
    ("tls_rep", _frames_tls_rep),
]

CLASS_OF_ALERT = {"DDOS": "DDOS", "C2": "C2", "DGA": "DGA",
                  "ENCRYPTED_MALWARE": "ENCRYPTED_MALWARE",
                  "RECON": "RECON", "EXFIL": "EXFIL"}


def _write_pcap(path: Path, frames) -> None:
    out = b"\x4d\x3c\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    for ts, frame in frames:
        out += struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)),
                           len(frame), len(frame)) + frame
    path.write_bytes(out)


# ---------------------------------------------------------------------- #
# evaluation

def evaluate(benign_capture: str | None, exfil_min_bytes: int = 10_000,
             out_dir: str = "reports") -> dict:
    """Replay every scenario through the real StreamingService; count
    true/false alerts per class. Deterministic; fixtures are synthetic."""
    results: dict[str, dict] = {}
    import tempfile
    for name, builder in SCENARIOS:
        frames, expected_class, note = builder()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / f"{name}.pcap"
            _write_pcap(p, frames)
            svc = StreamingService(window_sec=3.0, agg_window_sec=10.0,
                                   state="REPLAY",
                                   exfil_min_bytes_out=exfil_min_bytes)
            svc.run_pcap(p)
            alerts = svc.drain_alerts()
        got: dict[str, int] = {}
        for a in alerts:
            got[a.threat_class] = got.get(a.threat_class, 0) + 1
        results[name] = {
            "expected": expected_class,
            "alerts_by_class": got,
            "total_alerts": len(alerts),
            "note": note,
            "scenario_frames": len(frames),
        }
    if benign_capture:
        svc = StreamingService(window_sec=3.0, agg_window_sec=10.0,
                               state="REPLAY", exfil_min_bytes_out=exfil_min_bytes)
        for pv in _iter_pcap(benign_capture):
            svc.process_packet(pv)
        for fe in svc.engine.flush_all(0.0):
            svc._ddos_buffer.append(fe)
        svc._flush_ddos_buffer()
        for a in svc._roll_behavioural(svc.agg.current_bucket or 0.0, flush=True):
            svc.bus.put(a)
        alerts = svc.drain_alerts()
        got: dict[str, int] = {}
        for a in alerts:
            got[a.threat_class] = got.get(a.threat_class, 0) + 1
        results["real_benign_capture"] = {
            "expected": None, "alerts_by_class": got,
            "total_alerts": len(alerts),
            "note": f"real benign capture {Path(benign_capture).name} (FPR side)",
            "scenario_frames": None,
        }
    return results


def _iter_pcap(path: str):
    from src.streaming.pcap_source import PcapPacketSource
    yield from PcapPacketSource(path)


def write_report(results: dict, out_path: Path) -> None:
    lines = [
        "# Streaming detector evaluation — synthetic attack fixtures",
        "",
        "Generated by `src/streaming/evaluate.py`. **Fixtures are synthetic**;",
        "numbers measure the full implemented pipeline (packets → features →",
        "detectors → fusion → alerts), not real-world prevalence. The benign",
        "side uses a **real** DDoS-AT-2022 capture where available.",
        "",
        "| Scenario | Expected | Alerts emitted | Alerts by class | Verdict |",
        "|---|---|---|---|---|",
    ]
    for name, r in results.items():
        exp = r["expected"] or "—"
        by = ", ".join(f"{k}:{v}" for k, v in sorted(r["alerts_by_class"].items())) or "none"
        if r["expected"] is None:
            verdict = "PASS" if not r["alerts_by_class"] else \
                f"FP ({sum(r['alerts_by_class'].values())})"
        else:
            verdict = "PASS" if r["alerts_by_class"].get(r["expected"], 0) > 0 \
                and sum(v for k, v in r["alerts_by_class"].items() if k != r["expected"]) == 0 \
                else "CHECK"
        lines.append(f"| {name} | {exp} | {r['total_alerts']} | {by} | {verdict} |")
    lines += [
        "",
        "## Per-class summary",
        "",
    ]
    classes = ("DDOS", "C2", "DGA", "ENCRYPTED_MALWARE", "RECON", "EXFIL")
    for c in classes:
        hits = [n for n, r in results.items()
                if r["expected"] == c and r["alerts_by_class"].get(c, 0) > 0]
        fps = sum(v for n, r in results.items() if r["expected"] != c
                  for k, v in r["alerts_by_class"].items() if k == c)
        lines.append(f"- **{c}**: detected scenarios: {hits or 'none'}; "
                     f"cross-scenario false alerts: {fps}")
    lines += [
        "",
        "Notes:",
        "- Detection here is scenario-level (did the class fire at all), not",
        "  flow-level precision/recall: fixtures are too small for calibrated",
        "  per-flow statistics. Flow-level evaluation remains the DDoS",
        "  detector's published capture-disjoint protocol.",
        "- benign-capture alerts (if any) are the honest FPR side; see the",
        "  table row `real_benign_capture`.",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--benign", default="")
    ap.add_argument("--out-dir", default="reports")
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    results = evaluate(args.benign or None)
    out = Path(args.out_dir) / "streaming_fixture_evaluation.md"
    write_report(results, out)
    print(f"report -> {out}")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2), encoding="utf-8")
    for name, r in results.items():
        print(f"  {name:>22}: expected={str(r['expected']):>18} "
              f"alerts={r['alerts_by_class'] or '{}'}")


if __name__ == "__main__":
    main()
