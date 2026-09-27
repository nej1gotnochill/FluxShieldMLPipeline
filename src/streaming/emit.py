"""Dashboard bridge: real AlertEvents -> DATA_CONTRACT.md document.

Replaces the synthetic live path. LIVE mode is built exclusively from alerts
that flowed through the streaming service; REPLAY/SIMULATED documents are
written by the same bridge but with meta.source explicitly tagged and the
AlertEvent.state field preserved per event. No risk value in a LIVE document
is ever generated outside detector fusion.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any

from schema import AlertEvent

# Display-only mapping to MITRE technique ids for the UI. These labels do not
# assert attribution beyond the detector class that fired.
TECHNIQUE_ID = {
    "DDOS": "T1498", "C2": "T1071", "DGA": "T1568",
    "ENCRYPTED_MALWARE": "T1573", "RECON": "T1046", "EXFIL": "T1041",
}


class DashboardBridge:
    def __init__(self, path: str = "data.json", *, max_alerts: int = 200,
                 max_windows: int = 180, max_incidents: int = 20) -> None:
        self.path = path
        self.metrics_snapshot: dict = {}
        self.alerts: deque[AlertEvent] = deque(maxlen=max_alerts)
        self.risk_by_bucket: OrderedDict[float, dict] = OrderedDict()
        self.hosts: dict[str, dict] = {}
        self.incidents: OrderedDict[tuple, dict] = OrderedDict()
        self.max_windows = max_windows
        self.max_incidents = max_incidents

    # ------------------------------------------------------------------ #
    def ingest(self, a: AlertEvent) -> None:
        self.alerts.append(a)
        bucket = self._bucket_of(a)
        slot = self.risk_by_bucket.setdefault(
            bucket, {"risk": 0.0, "alerts": 0, "pps": 0.0,
                     "stage": "", "technique": "", "target": ""})
        slot["risk"] = max(slot["risk"], a.risk)
        slot["alerts"] += 1
        pps = a.evidence.get(a.threat_class, {}).get("packets_per_sec") \
            if isinstance(a.evidence.get(a.threat_class), dict) else None
        if pps:
            slot["pps"] = max(slot["pps"], float(pps))
        slot["stage"] = a.threat_class
        slot["technique"] = a.subtype
        slot["target"] = a.destination_ip or a.source_ip

        host = a.source_ip
        h = self.hosts.setdefault(host, {"risk": 0.0, "classes": set(),
                                         "alerts": 0, "dst": a.destination_ip})
        h["risk"] = max(h["risk"], a.risk)
        h["classes"].add(a.threat_class)
        h["alerts"] += 1

        key = (a.threat_class, a.subtype, a.source_ip)
        inc = self.incidents.get(key)
        if inc is None:
            inc = {"id": f"INC-{len(self.incidents)+1:04d}", "first": a.timestamp,
                   "first_ts_epoch": self._ts_epoch(a.timestamp), "last_ts": 0.0,
                   "peak": 0.0, "alerts": 0, "klass": a.threat_class,
                   "subtype": a.subtype, "src": a.source_ip, "dst": a.destination_ip}
            self.incidents[key] = inc
        inc["peak"] = max(inc["peak"], a.risk)
        inc["alerts"] += 1
        inc["last_ts"] = max(inc["last_ts"], self._ts_epoch(a.timestamp))
        while len(self.incidents) > self.max_incidents:
            self.incidents.popitem(last=False)
        while len(self.risk_by_bucket) > self.max_windows:
            self.risk_by_bucket.popitem(last=False)

    # ------------------------------------------------------------------ #
    def write(self, *, mode: str, source: str, registry_rows: list[dict],
              metrics_snapshot: dict | None = None, threshold: float = 0.5,
              fixture_eval: dict | None = None) -> str:
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.metrics_snapshot = metrics_snapshot or {}
        doc: dict[str, Any] = {
            "meta": {"schema_version": 1, "generated_at": now,
                     "source": f"{source}-{mode.lower()}",
                     "mode": mode},
            "ml": {
                "model": registry_rows[0]["name"] if registry_rows else "none",
                "modelCount": len(registry_rows),
                "calibration": registry_rows[0].get("calibration", "-") if registry_rows else "-",
                "threshold": threshold,
                "features": int(registry_rows[0]["features"]) if registry_rows else 0,
                "evalProtocol": registry_rows[0].get("evaluation", "-") if registry_rows else "-",
                "registry": registry_rows,
            },
            "windows": self._windows_rows(threshold),
            "hosts": self._hosts_rows(),
            "incidents": self._incident_rows(),
            "events": self._event_rows(),
            "alerts": self._alert_rows(),
            "streaming": self._streaming_rows(registry_rows),
            "overview": {
                "observedRisk": max((a.risk for a in self.alerts), default=0.0),
                "throughput": (metrics_snapshot or {}).get("packets_per_sec", 0),
                "flows": (metrics_snapshot or {}).get("flows_scored", 0),
                "packets": (metrics_snapshot or {}).get("packets_parsed", 0),
                "pipeline": "streaming",
                "activeThreatClasses": sorted({a.threat_class for a in self.alerts}),
            },
        }
        if fixture_eval:
            doc["ml"]["fixtureEval"] = fixture_eval
        # measured ML data from the repo's own reports (final test, causal
        # early-detection windows, 4-model comparison, Track B) — the Model
        # screen renders these instead of built-in fixtures when present
        from ml_data import build as build_ml_data
        for k, v in build_ml_data().items():
            doc["ml"][k] = v
        if metrics_snapshot:
            doc["overview"]["streamingMetrics"] = metrics_snapshot
        _atomic_write_json(doc, self.path)
        return self.path

    def _streaming_rows(self, registry_rows: list[dict]) -> dict:
        """Detector health + latency metrics for the streaming strip.
        kind is derived honestly: a sigmoid-calibrated detector is ML, a
        rule threshold is a rule."""
        return {
            "detectors": [
                {"name": r.get("name", "?"), "version": r.get("version", "—"),
                 "kind": "ml" if r.get("calibration") == "sigmoid" else "rule",
                 "threshold": r.get("threshold", 0),
                 "calibration": r.get("calibration", "—"),
                 "status": r.get("status", "ok"),
                 "last_error": r.get("last_error", ""),
                 "evaluation": r.get("evaluation", "—")}
                for r in registry_rows
            ],
            "metrics": self.metrics_snapshot,
        }

    def _alert_rows(self) -> list[dict]:
        """Full AlertEvent records (latest last) — the UI's evidence viewer
        consumes exactly these; nothing is summarized away."""
        rows = []
        for a in self.alerts:
            rows.append({
                "event_id": a.event_id,
                "timestamp": a.timestamp,
                "flow_id": a.flow_id,
                "src": a.source_ip, "dst": a.destination_ip,
                "sport": a.source_port, "dport": a.destination_port,
                "proto": a.protocol,
                "threat_class": a.threat_class, "subtype": a.subtype,
                "prediction": a.prediction,
                "confidence": a.confidence, "risk": a.risk,
                "window_sec": a.observation_window_sec,
                "model": a.model.to_dict(),
                "evidence": a.evidence,
                "state": a.state,
            })
        return rows

    # ------------------------------------------------------------------ #
    def _bucket_of(self, a: AlertEvent) -> float:
        return float(int(self._ts_epoch(a.timestamp) // 10) * 10)

    @staticmethod
    def _ts_epoch(ts: str) -> float:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return datetime.now(timezone.utc).timestamp()     # 10 s display buckets

    def _windows_rows(self, threshold: float) -> list[dict]:
        rows = []
        for i, (b, slot) in enumerate(self.risk_by_bucket.items()):
            rows.append({
                "i": i, "risk": round(slot["risk"], 4),
                "peak": round(slot["risk"], 4), "pps": slot["pps"],
                "flow": slot["alerts"], "alert": slot["risk"] >= threshold,
                "stage": slot["stage"], "technique": slot["technique"],
                "target": slot["target"], "tsec": b % 86400,
            })
        return rows

    def _hosts_rows(self) -> list[dict]:
        out = []
        for ip, h in self.hosts.items():
            risk = round(h["risk"], 4)
            out.append({
                "id": ip, "ip": ip, "zone": "observed", "kind": "host",
                "risk": risk,
                "state": "high" if risk >= 0.8 else "susp" if risk >= 0.5 else "norm",
                "tech": "/".join(sorted(h["classes"])),
                "flows": h["alerts"],
            })
        return out

    def _incident_rows(self) -> list[dict]:
        rows = []
        for inc in self.incidents.values():
            risk = inc["peak"]
            span = inc.get("last_ts", 0.0) - inc.get("first_ts_epoch", 0.0)
            dur = (f"{span:.0f}s" if span >= 1 else "<1s") if span > 0 else "-"
            opened = inc["first"].split("T")[-1][:8] if "T" in inc["first"] else inc["first"]
            rows.append({
                "id": inc["id"],
                "sev": "CRIT" if risk >= 0.8 else "HIGH" if risk >= 0.6 else "MED",
                "status": "TRIAGING",
                "tid": TECHNIQUE_ID.get(inc["klass"], "T1498"),
                "tech": inc["subtype"] or inc["klass"],
                "target": inc["dst"] or inc["src"],
                "ip": inc["src"],
                "peak": round(risk, 4),
                "lead": 0.0,                # no forecast layer yet: 0 = unknown, UI hides it
                "dur": dur,
                "analyst": "",              # unassigned (no analyst workflow yet)
                "alerts": inc["alerts"],
                "opened": opened,
                "evidence": inc["alerts"],
            })
        return rows

    def _event_rows(self) -> list[dict]:
        rows = []
        for a in list(self.alerts)[-50:]:
            rows.append({
                "ts": a.timestamp,
                "sev": "CRIT" if a.risk >= 0.8 else "WARN" if a.risk >= 0.5 else "INFO",
                "src": f"{a.model.name}@{a.state}",
                "host": a.source_ip,
                "msg": f"{a.threat_class}/{a.subtype} risk={a.risk:.3f} "
                       f"conf={a.confidence:.3f} -> {a.destination_ip or '-'}",
            })
        return rows


def _atomic_write_json(doc: dict, path: str) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
