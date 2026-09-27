"""Bounded, TTL-expiring state store for cross-flow aggregation.

Backs the behavioural detectors (recon fan-out, C2 periodicity, exfil
baselines). Design rules from the brief:

  * keyed by host / source / destination / source-destination pair / window;
  * bounded memory: per-namespace capacity caps with oldest-last eviction;
  * stale state expires deterministically (no infinite growth);
  * no detector writes to the dashboard through this store.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Callable, Iterator


class TTLStateStore:
    """Namespace-partitioned dict with TTL expiry and capacity eviction."""

    def __init__(self, ttl_sec: float = 300.0, capacity: int = 100_000) -> None:
        if ttl_sec <= 0:
            raise ValueError("ttl_sec must be positive")
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.ttl_sec = float(ttl_sec)
        self.capacity = int(capacity)
        self._ns: dict[str, OrderedDict[Any, tuple[float, Any]]] = {}
        self._evicted = 0

    # ------------------------------------------------------------------ #
    def get(self, ns: str, key: Any, now: float | None = None) -> Any:
        now = time.monotonic() if now is None else now
        bucket = self._ns.get(ns)
        if not bucket:
            return None
        item = bucket.get(key)
        if item is None:
            return None
        exp, val = item
        if now >= exp:
            del bucket[key]
            return None
        return val

    def set(self, ns: str, key: Any, value: Any, now: float | None = None,
            ttl_sec: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        ttl = self.ttl_sec if ttl_sec is None else float(ttl_sec)
        bucket = self._ns.setdefault(ns, OrderedDict())
        bucket[key] = (now + ttl, value)
        bucket.move_to_end(key)
        while len(bucket) > self.capacity:
            bucket.popitem(last=False)
            self._evicted += 1

    def update(self, ns: str, key: Any, fn: Callable[[Any], Any],
               default: Callable[[], Any], now: float | None = None,
               ttl_sec: float | None = None) -> Any:
        """get-modify-set under one call; fn receives the value (or default())."""
        cur = self.get(ns, key, now)
        if cur is None:
            cur = default()
        new = fn(cur)
        self.set(ns, key, new, now, ttl_sec=ttl_sec)
        return new

    def expire(self, now: float | None = None) -> int:
        """Drop expired entries across all namespaces; returns count removed."""
        now = time.monotonic() if now is None else now
        removed = 0
        for bucket in self._ns.values():
            dead = [k for k, (exp, _) in bucket.items() if now >= exp]
            for k in dead:
                del bucket[k]
                removed += 1
        return removed

    # ------------------------------------------------------------------ #
    def items(self, ns: str) -> Iterator[tuple[Any, Any]]:
        bucket = self._ns.get(ns)
        if not bucket:
            return
        for k, (_exp, v) in list(bucket.items()):
            yield k, v

    def size(self, ns: str | None = None) -> int:
        if ns is not None:
            return len(self._ns.get(ns, ()))
        return sum(len(b) for b in self._ns.values())

    @property
    def evicted(self) -> int:
        return self._evicted
