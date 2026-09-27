"""Bounded event bus with drop accounting.

Alerts flow detector -> fusion -> bus -> dashboard bridge. The bus is bounded
(backpressure policy: drop NEWEST under overflow, count the drop — a monitor
must never block the passive pipeline). Queue depth is observed by metrics.
"""
from __future__ import annotations

import queue
from typing import Any


class BoundedEventBus:
    def __init__(self, maxsize: int = 10_000) -> None:
        if maxsize <= 0:
            raise ValueError("maxsize must be positive")
        self._q: queue.Queue = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self.emitted = 0

    def put(self, item: Any) -> bool:
        try:
            self._q.put_nowait(item)
            self.emitted += 1
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def get(self, timeout: float | None = None) -> Any | None:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self) -> list[Any]:
        out = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                return out

    def depth(self) -> int:
        return self._q.qsize()
