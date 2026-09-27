"""Transparent risk fusion.

The formula is deliberately visible and configurable (configs/streaming.yaml):

    overall_risk = max(class_scores)                      # primary signal
                   + persistence_bonus * repeat_windows    # temporal persistence
                   + cross_host_bonus * (hosts_flagged - 1)  # cross-host evidence

clamped to [0, 1]. No hidden weights anywhere else in the codebase; every
alert's evidence dict records the components that produced its risk.
"""
from __future__ import annotations

from typing import Any

from detectors import DetectorResult
from schema import AlertEvent, ModelIdentity, prediction_for


class ThreatFusion:
    def __init__(self, *, persistence_bonus: float = 0.05,
                 cross_host_bonus: float = 0.02,
                 persistence_windows_required: int = 2,
                 suspicious_floor: float = 0.5,
                 attack_floor: float = 0.8) -> None:
        self.persistence_bonus = float(persistence_bonus)
        self.cross_host_bonus = float(cross_host_bonus)
        self.persistence_windows_required = int(persistence_windows_required)
        self.suspicious_floor = float(suspicious_floor)
        self.attack_floor = float(attack_floor)
        self._persistence: dict[tuple, int] = {}   # (class, entity) -> consecutive windows

    # ------------------------------------------------------------------ #
    def fuse(self, results: list[DetectorResult], *,
             entity: str, hosts_flagged: int = 1) -> dict[str, Any]:
        """Fuse detector results for one entity/window into the alert payload.

        Returns {threat_class, subtype, confidence, risk, secondary, evidence}
        or None when nothing is active.
        """
        active = [r for r in results if r.active]
        if not active:
            # decay persistence for every class on quiet windows
            for k in [k for k in self._persistence if k[1] == entity]:
                self._persistence[k] = 0
            return None
        active.sort(key=lambda r: r.score, reverse=True)
        primary = active[0]

        key = (primary.threat_class, entity)
        if primary.score >= self.suspicious_floor:
            self._persistence[key] = self._persistence.get(key, 0) + 1
        else:
            self._persistence[key] = 0
        repeats = self._persistence[key]

        risk = primary.score
        if repeats >= self.persistence_windows_required:
            risk += self.persistence_bonus * (repeats - self.persistence_windows_required + 1)
        if hosts_flagged > 1:
            risk += self.cross_host_bonus * (hosts_flagged - 1)
        risk = min(max(risk, 0.0), 1.0)

        confidence = max(primary.confidence,
                         max((r.confidence for r in active[1:]), default=0.0))
        secondary = [
            {"threat_class": r.threat_class, "score": round(r.score, 4)}
            for r in active[1:]
        ]
        evidence = {}
        for r in active:
            evidence[r.threat_class] = r.evidence
        evidence["_fusion"] = {
            "formula": "max(class_scores) + persistence_bonus*repeats "
                       "+ cross_host_bonus*(hosts_flagged-1)",
            "persistence_windows": repeats,
            "hosts_flagged": hosts_flagged,
            "weights": {
                "persistence_bonus": self.persistence_bonus,
                "cross_host_bonus": self.cross_host_bonus,
            },
        }
        return {
            "threat_class": primary.threat_class,
            "subtype": primary.subtype,
            "confidence": confidence,
            "risk": risk,
            "secondary": secondary,
            "evidence": evidence,
            "window_start": primary.window_start,
            "window_end": primary.window_end,
        }

    # ------------------------------------------------------------------ #
    def to_alert(self, fused: dict[str, Any], *, flow_id: str, src: str, dst: str,
                 sport: int, dport: int, proto: str, timestamp: str,
                 window_sec: float, model: ModelIdentity, latency_ms: float,
                 state: str = "LIVE") -> AlertEvent:
        prediction = prediction_for(fused["risk"], self.suspicious_floor, self.attack_floor)
        return AlertEvent(
            event_id=AlertEvent.new_event_id(),
            timestamp=timestamp,
            flow_id=flow_id,
            source_ip=src,
            destination_ip=dst,
            source_port=sport,
            destination_port=dport,
            protocol=proto,
            threat_class=fused["threat_class"],
            subtype=fused["subtype"],
            prediction=prediction,
            confidence=round(min(max(fused["confidence"], 0.0), 1.0), 4),
            risk=round(min(max(fused["risk"], 0.0), 1.0), 4),
            stage=fused["threat_class"],
            technique=fused["subtype"] or fused["threat_class"],
            observation_window_sec=window_sec,
            evidence=fused["evidence"],
            model=model,
            latency_ms=round(latency_ms, 3),
            state=state,
            secondary=fused["secondary"],
        )
