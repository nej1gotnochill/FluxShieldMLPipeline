"""Replay runner: feed a pcap (read-only) through the streaming service and
emit the dashboard document + alert dump.

This is the LIVE-path code running over recorded traffic: every risk value in
the emitted document comes from detector fusion on real flow evidence. The
document's meta.source is tagged "replay" so the UI can label it REPLAY.

Usage:
    python -m src.streaming.replay --pcap path/to/capture.pcap
    python -m src.streaming.replay --pcap ... --out data.json --alerts alerts.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.streaming import service as svc_mod
from src.streaming.emit import DashboardBridge


def _load_frozen(models_dir: Path):
    """Load the frozen calibrated DDoS artifacts (no retraining, no changes)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from inference import load_model
    from feature_engineering import FEATURE_NAMES
    model, th = load_model(models_dir)
    thresholds = th.get("thresholds", {})
    t_op = thresholds.get("t_op", thresholds.get("t_f1", 0.5))
    meta = {}
    mp = models_dir / "model_metadata.json"
    if mp.exists():
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
    return model, float(t_op), list(FEATURE_NAMES), meta


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", default="data.json")
    ap.add_argument("--alerts", default="")
    ap.add_argument("--window", type=float, default=3.0)
    ap.add_argument("--agg-window", type=float, default=10.0)
    ap.add_argument("--no-ddos", action="store_true",
                    help="skip the frozen DDoS model (rule detectors only)")
    args = ap.parse_args()

    if not Path(args.pcap).exists():
        sys.exit(f"pcap not found: {args.pcap}")

    ddos_model, ddos_threshold, ddos_features, meta = (None, 0.5, None, {})
    if not args.no_ddos:
        try:
            repo_root = Path(__file__).resolve().parents[2]
            ddos_model, ddos_threshold, ddos_features, meta = _load_frozen(repo_root / "models")
        except FileNotFoundError as e:
            print(f"WARNING: frozen DDoS artifacts unavailable ({e}); rule detectors only")

    svc = svc_mod.StreamingService(
        window_sec=args.window, agg_window_sec=args.agg_window,
        state="REPLAY", ddos_model=ddos_model,
        ddos_threshold=ddos_threshold, ddos_features=ddos_features)
    snap = svc.run_pcap(args.pcap)
    alerts = svc.drain_alerts()

    # measured fixture evaluation (if present) -> displayed on the Model page
    fixture_eval = None
    fe_path = Path(__file__).resolve().parents[2] / "reports" / "streaming_fixture_evaluation.md"
    json_path = fe_path.with_suffix(".json")
    if json_path.exists():
        try:
            fixture_eval = json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            fixture_eval = None

    bridge = DashboardBridge(path=args.out)
    for a in alerts:
        bridge.ingest(a)

    registry = []
    if ddos_model is not None:
        d = svc.registry.get("ddos")
        registry.append({
            "name": "ddos-frozen-et", "version": "1.0", "kind": "ml",
            "features": len(ddos_features),
            "calibration": "sigmoid",
            "threshold": ddos_threshold,
            "status": d.status if d else "ok",
            "last_error": (d.last_error or "") if d else "",
            "evaluation": ("capture-disjoint A1/A2/B; untouched final test "
                           f"P=0.999998 R=0.997849 (trained {meta.get('trained_at', 'n/a')})"),
        })
    for rule_name, det in (("recon", svc.registry.get("recon")),
                           ("c2", svc.registry.get("c2")),
                           ("dns", svc.registry.get("dns")),
                           ("tls", svc.registry.get("tls")),
                           ("exfil", svc.registry.get("exfil"))):
        if det is None:
            continue
        registry.append({
            "name": f"rule-{rule_name}", "version": det.version, "kind": "rule",
            "features": 0, "calibration": "rule", "threshold": det.suspicious_floor,
            "status": det.status, "last_error": det.last_error or "",
            "evaluation": "synthetic-fixture scenario + real benign FPR (see reports/)"
            if rule_name != "tls" else
            "cleartext-handshake only; fixture scenario (DATA-LIMITED)",
        })

    path = bridge.write(mode="REPLAY", source="netra-streaming",
                        registry_rows=registry, metrics_snapshot=snap,
                        threshold=ddos_threshold, fixture_eval=fixture_eval)

    if args.alerts:
        with open(args.alerts, "w", encoding="utf-8") as fh:
            for a in alerts:
                fh.write(a.to_json() + "\n")

    by_class: dict[str, int] = {}
    for a in alerts:
        by_class[a.threat_class] = by_class.get(a.threat_class, 0) + 1
    print(f"pcap: {args.pcap}")
    print(f"alerts: {len(alerts)} by class: {by_class or '{}'}")
    print(f"dashboard document: {path}")
    lat = snap.get("latency", {})
    print(f"throughput: {snap.get('packets_per_sec', 0)} pkt/s, "
          f"{snap.get('flows_per_sec', 0)} flows/s")
    print(f"latency ms: e2e p50={lat.get('end_to_end', {}).get('p50_ms')} "
          f"p95={lat.get('end_to_end', {}).get('p95_ms')} "
          f"p99={lat.get('end_to_end', {}).get('p99_ms')}")


if __name__ == "__main__":
    main()
