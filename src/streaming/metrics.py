"""Internal operational metrics for the streaming loop.

Counters (events received, alerts emitted/dropped, queue depth peaks, state
size) plus per-stage latency recorders exposing p50/p95/p99. Pure stdlib; no
external metrics dependency. Consumed by the service and surfaced in the
dashboard document (meta.source stays the only UI-visible identity).
"""
from __future__ import annotations

import time
from collections import deque
from typing import Deque


class LatencyHist:
    """Bounded-latency recorder (keeps the last `keep` samples)."""

    def __init__(self, keep: int = 20_000) -> None:
        self.samples: Deque[float] = deque(maxlen=keep)

    def add(self, seconds: float) -> None:
        self.samples.append(seconds)

    def percentile(self, p: float) -> float:
        if not self.samples:
            return 0.0
        s = sorted(self.samples)
        i = min(len(s) - 1, max(0, int(round((p / 100.0) * (len(s) - 1)))))
        return s[i]

    def ms_summary(self) -> dict[str, float]:
        return {
            "p50_ms": round(self.percentile(50) * 1e3, 3),
            "p95_ms": round(self.percentile(95) * 1e3, 3),
            "p99_ms": round(self.percentile(99) * 1e3, 3),
            "n": len(self.samples),
        }


class Metrics:
    def __init__(self) -> None:
        self.counters: dict[str, int] = {}
        self.stage_latency: dict[str, LatencyHist] = {
            "feature_update": LatencyHist(),
            "detector": LatencyHist(),
            "alert_emit": LatencyHist(),
            "end_to_end": LatencyHist(),
        }
        self.peak_queue_depth = 0
        self.peak_state_size = 0
        self.started = time.monotonic()

    # ------------------------------------------------------------------ #
    def incr(self, name: str, by: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + by

    def stage(self, name: str, seconds: float) -> None:
        self.stage_latency[name].add(seconds)

    def observe_queue(self, depth: int) -> None:
        if depth > self.peak_queue_depth:
            self.peak_queue_depth = depth

    def observe_state(self, size: int) -> None:
        if size > self.peak_state_size:
            self.peak_state_size = size

    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict:
        lat = {k: v.ms_summary() for k, v in self.stage_latency.items()}
        elapsed = max(time.monotonic() - self.started, 1e-9)
        return {
            "elapsed_sec": round(elapsed, 3),
            "events_received": self.counters.get("events_received", 0),
            "packets_parsed": self.counters.get("packets_parsed", 0),
            "flows_scored": self.counters.get("flows_scored", 0),
            "alerts_emitted": self.counters.get("alerts_emitted", 0),
            "alerts_dropped": self.counters.get("alerts_dropped", 0),
            "detector_errors": self.counters.get("detector_errors", 0),
            "degraded_mode": self.counters.get("degraded_mode", 0),
            "peak_queue_depth": self.peak_queue_depth,
            "peak_state_size": self.peak_state_size,
            "flows_per_sec": round(self.counters.get("flows_scored", 0) / elapsed, 1),
            "packets_per_sec": round(self.counters.get("packets_parsed", 0) / elapsed, 1),
            "latency": lat,
        }
