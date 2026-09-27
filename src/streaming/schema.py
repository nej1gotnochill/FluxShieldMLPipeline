"""Standardized alert-event schema (single authoritative contract).

Every alert produced by the streaming service is an AlertEvent. The dashboard
bridge consumes exactly these records; nothing synthesizes live alerts.

The brief's core requirement: timestamp, flow identifier, threat class,
confidence score, supporting evidence features. Model identity is embedded so
"risk 0.8" is always attributable to a specific detector version.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

THREAT_CLASSES = ("DDOS", "C2", "DGA", "ENCRYPTED_MALWARE", "RECON", "EXFIL")
PREDICTIONS = ("ATTACK", "SUSPICIOUS", "BENIGN")
STATES = ("LIVE", "REPLAY", "SIMULATED")


@dataclass(slots=True)
class ModelIdentity:
    """Which detector/model produced this alert (reproducibility)."""
    name: str
    version: str
    threshold: float

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "version": self.version, "threshold": self.threshold}


@dataclass(slots=True)
class AlertEvent:
    event_id: str
    timestamp: str          # RFC3339 UTC
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    threat_class: str       # one of THREAT_CLASSES
    subtype: str
    prediction: str         # one of PREDICTIONS
    confidence: float       # [0, 1]
    risk: float             # fused overall risk [0, 1]
    stage: str
    technique: str
    observation_window_sec: float
    evidence: dict[str, Any]
    model: ModelIdentity
    latency_ms: float
    state: str = "LIVE"     # LIVE | REPLAY | SIMULATED
    secondary: list[dict[str, float]] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    def __post_init__(self) -> None:
        errors: list[str] = []

        def _num(v: Any, name: str, lo: float, hi: float) -> None:
            if not isinstance(v, (int, float)) or isinstance(v, bool) \
               or v != v or v in (float("inf"), float("-inf")) or not (lo <= v <= hi):
                errors.append(f"{name}={v!r} outside [{lo}, {hi}]")

        if self.threat_class not in THREAT_CLASSES:
            errors.append(f"threat_class={self.threat_class!r} not in {THREAT_CLASSES}")
        if self.prediction not in PREDICTIONS:
            errors.append(f"prediction={self.prediction!r} not in {PREDICTIONS}")
        if self.state not in STATES:
            errors.append(f"state={self.state!r} not in {STATES}")
        _num(self.confidence, "confidence", 0.0, 1.0)
        _num(self.risk, "risk", 0.0, 1.0)
        if self.observation_window_sec <= 0:
            errors.append(f"observation_window_sec={self.observation_window_sec!r} must be > 0")
        if not isinstance(self.source_port, int) or not 0 <= self.source_port <= 65535:
            errors.append(f"source_port={self.source_port!r} invalid")
        if not isinstance(self.destination_port, int) or not 0 <= self.destination_port <= 65535:
            errors.append(f"destination_port={self.destination_port!r} invalid")
        if not self.evidence or not isinstance(self.evidence, dict):
            errors.append("evidence must be a non-empty dict (evidence-driven alerts)")
        if not isinstance(self.model, ModelIdentity):
            errors.append("model must be a ModelIdentity")
        if errors:
            raise ValueError("invalid AlertEvent: " + "; ".join(errors))

    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["model"] = self.model.to_dict()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    # ------------------------------------------------------------------ #
    @classmethod
    def now_ts(cls) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    @staticmethod
    def new_event_id() -> str:
        return uuid.uuid4().hex[:16]


def prediction_for(score: float, suspicious_floor: float, attack_floor: float) -> str:
    """Shared three-level mapping; thresholds come from detector config."""
    if score >= attack_floor:
        return "ATTACK"
    if score >= suspicious_floor:
        return "SUSPICIOUS"
    return "BENIGN"
