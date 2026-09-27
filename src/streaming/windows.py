"""Causal windowing over the shared Flow machinery.

Mirrors the causality model already validated in src/early_detection.py:

  * every observation window keeps its own Flow accumulators built with the
    SAME Flow class and flow_to_row() as the validated terminal extractor
    (one code path — no second parser, no second feature implementation);
  * an accumulator is FROZEN at the first packet with t > flow_start + W;
    later packets can neither update it nor re-create the same instance;
  * FEATURES are computed causally from in-window packets only; TERMINAL
    features (active_*/idle_*) become their in-window counterparts per the
    feature dictionary's early-window rule, exactly as in early_detection.

On top of that, live operation needs:
  * a terminal flow table with idle-timeout sweep (parity with the
    extractor's sweep(), incl. forced eviction of small flows under memory
    pressure from spoofed floods);
  * a reaper that force-closes window accumulators whose traffic went quiet
    (no future packet will arrive to trigger the freeze) — this is what makes
    alerting bounded in wall-clock time, not just in packet time.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from typing import Any

from feature_engineering import (
    FEATURE_NAMES, IDLE_GAP_S, MAX_TRACKED, PROTO_ICMP, PROTO_TCP, PROTO_UDP,
    SWEEP_EVERY, Flow, flow_to_row,
)
from pcap_source import PacketView, src_str

PROTO_NAME = {PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMP: "ICMP"}


@dataclass(slots=True)
class WindowConfig:
    window_sec: float = 3.0          # causal observation window W
    flow_timeout_sec: float = 120.0  # terminal idle timeout (dataset default)
    activity_timeout_sec: float = 1800.0
    max_packets_per_flow: int = 100_000
    reap_grace_sec: float = 2.0      # freeze window accumulators W + grace after quiet
    sweep_every_packets: int = 10_000


@dataclass(slots=True)
class FlowEvent:
    """A closed (frozen/ended) flow with its 66-feature row + context."""
    kind: str                # "window" | "terminal"
    window_sec: float
    row: dict[str, float]    # the 66-model-feature contract, exactly
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    start_ts: float
    end_ts: float
    n_packets: int
    flow: Flow = field(repr=False, default=None)  # raw accumulators (flag counts, IATs)
    ddos_result: object = field(repr=False, default=None)  # FrozenDDoSDetector result (set by service)


def _flow_meta(proto: int, fwd_key: tuple, fl: Flow) -> dict[str, Any]:
    _p, src_b, sport, dst_b, dport = fwd_key
    return {
        "flow_id": f"{proto}|{src_str(src_b)}|{sport}|{src_str(dst_b)}|{dport}",
        "src_ip": src_str(src_b), "dst_ip": src_str(dst_b),
        "src_port": int(sport), "dst_port": int(dport),
        "proto": PROTO_NAME.get(proto, str(proto)),
    }


class StreamingFlowEngine:
    """Consumes PacketViews; emits FlowEvents (window + terminal closures)."""

    def __init__(self, cfg: WindowConfig, metrics=None) -> None:
        self.cfg = cfg
        self.metrics = metrics
        self.w_flows: dict[tuple, Flow] = {}       # window accumulators
        self.w_frozen: dict[tuple, Flow] = {}      # frozen instances (reincarnation guard)
        self.t_flows: dict[tuple, Flow] = {}       # terminal accumulators
        self.t_meta: dict[tuple, tuple] = {}       # terminal key -> fwd_key
        self._n = 0
        self.counters = {"window_closed": 0, "terminal_closed": 0, "reaped": 0,
                         "evicted": 0, "pkt_cap": 0, "activity_cap": 0}

    # ------------------------------------------------------------------ #
    def on_packet(self, pv: PacketView) -> list[FlowEvent]:
        out: list[FlowEvent] = []
        self._n += 1
        out += self._update_window(pv)
        out += self._update_terminal(pv)
        if self._n % self.cfg.sweep_every_packets == 0:
            out += self._sweep(pv.ts)
        return out

    def sweep(self, now: float) -> list[FlowEvent]:
        """Public terminal-flow sweep (idle timeout + forced eviction)."""
        return self._sweep(now)

    def flush_all(self, now: float) -> list[FlowEvent]:
        """End-of-stream flush: close every open accumulator (window +
        terminal). Mirrors the offline extractor's final flush() at EOF so a
        replay produces complete flow evidence without changing mid-capture
        causality semantics."""
        out: list[FlowEvent] = []
        for k, fl in list(self.w_flows.items()):
            self.w_flows.pop(k, None)
            self.w_frozen[k] = fl
            out.append(self._make_event("window", self.cfg.window_sec, fl, k, now))
            self.counters["window_closed"] += 1
        for k, fl in list(self.t_flows.items()):
            self.t_flows.pop(k, None)
            self.t_meta.pop(k, None)
            out.append(self._make_event("terminal", 0.0, fl, k, now))
            self.counters["terminal_closed"] += 1
        return out

    def reap(self, now: float | None = None) -> list[FlowEvent]:
        """Force-close quiet window accumulators (call on wall-clock timer).
        Closed-by-reap accumulators are NOT retained as frozen instances:
        traffic resuming after a quiet period is a new burst and must start
        a fresh accumulator immediately, not wait out flow_timeout."""
        now = pv_time = now if now is not None else time.time()
        out: list[FlowEvent] = []
        horizon = self.cfg.window_sec + self.cfg.reap_grace_sec
        dead = [k for k, fl in self.w_flows.items() if now - fl.last > horizon]
        for k in dead:
            fl = self.w_flows.pop(k)
            out.append(self._make_event("window", self.cfg.window_sec, fl, k, fl.last))
            self.counters["reaped"] += 1
        return out

    # ------------------------------------------------------------------ #
    def _update_window(self, pv: PacketView) -> list[FlowEvent]:
        W = self.cfg.window_sec
        out: list[FlowEvent] = []
        fwd_key = (pv.proto, pv.src_b, pv.sport, pv.dst_b, pv.dport)
        bwd_key = (pv.proto, pv.dst_b, pv.dport, pv.src_b, pv.sport)
        fl = self.w_flows.get(fwd_key)
        if fl is None:
            fl = self.w_flows.get(bwd_key)   # response packet on an existing convo
        if fl is None:
            # frozen-instance guard on BOTH keys (early_detection semantics:
            # a frozen instance cannot be revived within flow_timeout; after
            # reap/eviction a genuinely new burst may start a new instance)
            for fk in (fwd_key, bwd_key):
                frozen = self.w_frozen.get(fk)
                if frozen is not None and (pv.ts - frozen.last) <= self.cfg.flow_timeout_sec:
                    return out               # same instance: already emitted
            fl = Flow(pv.proto, fwd_key, pv.ts)  # new instance
            self.w_flows[fwd_key] = fl
        if pv.ts > fl.start + W:
            # freeze BEFORE updating: this packet belongs to the future
            self.w_flows.pop(fl.fwd_key, None)
            self.w_frozen[fl.fwd_key] = fl
            out.append(self._make_event("window", W, fl, fl.fwd_key, pv.ts))
            self.counters["window_closed"] += 1
            fl = Flow(pv.proto, fwd_key, pv.ts)   # fresh instance for the future
            self.w_flows[fwd_key] = fl
        self._apply(fl, pv, fl.fwd_key == fwd_key)
        if fl.fwd_n + fl.bwd_n >= self.cfg.max_packets_per_flow:
            self.w_flows.pop(fl.fwd_key, None)
            self.w_frozen[fl.fwd_key] = fl
            out.append(self._make_event("window", W, fl, fl.fwd_key, pv.ts))
            self.counters["pkt_cap"] += 1
        if fl.last - fl.start >= self.cfg.activity_timeout_sec:
            self.w_flows.pop(fl.fwd_key, None)
            self.w_frozen[fl.fwd_key] = fl
            out.append(self._make_event("window", W, fl, fl.fwd_key, pv.ts))
            self.counters["activity_cap"] += 1
        # Memory guard (parity with the extractor's forced sweep): floods of
        # single-packet flows never freeze on their own (no second packet to
        # cross the window boundary). When over MAX_TRACKED, force-close the
        # OLDEST accumulators (insertion order) as window events — their
        # evidence still reaches every detector. Mirrors the extractor's
        # small-first eviction for spoofed floods.
        if len(self.w_flows) > MAX_TRACKED:
            n_evict = MAX_TRACKED // 2
            for _ in range(n_evict):
                k, fl2 = next(iter(self.w_flows.items()))
                self.w_flows.pop(k, None)
                self.w_frozen[k] = fl2
                out.append(self._make_event("window", W, fl2, k, pv.ts))
                self.counters["evicted"] += 1
        if len(self.w_frozen) > 2 * MAX_TRACKED:
            # Frozen instances older than flow_timeout can never block a new
            # instance (the reincarnation check already treats them as
            # eligible), so dropping them is semantically safe. Floods close
            # millions of 1-packet instances; prune oldest-first.
            cutoff = pv.ts - self.cfg.flow_timeout_sec
            while len(self.w_frozen) > MAX_TRACKED:
                k3, fl3 = next(iter(self.w_frozen.items()))
                if fl3.last > cutoff:
                    break
                self.w_frozen.pop(k3, None)
        return out

    def _update_terminal(self, pv: PacketView) -> list[FlowEvent]:
        out: list[FlowEvent] = []
        fwd_key = (pv.proto, pv.src_b, pv.sport, pv.dst_b, pv.dport)
        fl = self.t_flows.get(fwd_key)
        is_new = False
        if fl is None:
            bwd = (pv.proto, pv.dst_b, pv.dport, pv.src_b, pv.sport)
            fl = self.t_flows.get(bwd)
            if fl is None:
                fl = Flow(pv.proto, fwd_key, pv.ts)
                self.t_flows[fwd_key] = fl
                self.t_meta[fwd_key] = fwd_key
                is_new = True
        self._apply(fl, pv, is_new)
        if fl.last - fl.start >= self.cfg.activity_timeout_sec:
            self.t_flows.pop(fl.fwd_key, None)
            self.t_meta.pop(fl.fwd_key, None)
            out.append(self._make_event("terminal", 0.0, fl, fl.fwd_key, pv.ts))
            self.counters["terminal_closed"] += 1
        return out

    def _sweep(self, now: float) -> list[FlowEvent]:
        out: list[FlowEvent] = []
        dead = [k for k, fl in self.t_flows.items()
                if now - fl.last >= self.cfg.flow_timeout_sec]
        for k in dead:
            fl = self.t_flows.pop(k)
            self.t_meta.pop(k, None)
            out.append(self._make_event("terminal", 0.0, fl, k, now))
            self.counters["terminal_closed"] += 1
        if len(self.t_flows) > MAX_TRACKED:
            small = [k for k, fl in self.t_flows.items() if fl.fwd_n + fl.bwd_n <= 2]
            for k in small:
                fl = self.t_flows.pop(k)
                self.t_meta.pop(k, None)
                out.append(self._make_event("terminal", 0.0, fl, k, now))
                self.counters["evicted"] += 1
            if len(self.t_flows) > MAX_TRACKED:
                old = sorted(self.t_flows.items(), key=lambda kv: kv[1].last)[:MAX_TRACKED // 2]
                for k, _fl in old:
                    fl = self.t_flows.pop(k)
                    self.t_meta.pop(k, None)
                    out.append(self._make_event("terminal", 0.0, fl, k, now))
                    self.counters["evicted"] += 1
        return out

    # ------------------------------------------------------------------ #
    def _apply(self, fl: Flow, pv: PacketView, is_new: bool) -> None:
        """Packet update — byte-for-byte the terminal extractor's flow-update
        math (IAT/active/idle accumulation, directional counters, flags)."""
        fwd_key = (pv.proto, pv.src_b, pv.sport, pv.dst_b, pv.dport)
        bwd_key = (pv.proto, pv.dst_b, pv.dport, pv.src_b, pv.sport)
        ts = pv.ts
        if is_new:
            fl.proto = pv.proto
            fl.fwd_key = fwd_key
            if pv.proto == PROTO_TCP:
                fl.init_fwd_win = pv.win
        if fl.fwd_n + fl.bwd_n > 0:
            d_all = ts - fl.last
            fl.all_iat.add(d_all)
            if d_all > IDLE_GAP_S:
                fl.idle.add(d_all)
                if fl.active_cur > 0:
                    fl.active.add(fl.active_cur)
                    fl.active_cur = 0.0
            else:
                fl.active_cur += d_all
        is_fwd = fl.fwd_key == fwd_key
        if is_fwd:
            if fl.fwd_n > 0:
                fl.fwd_iat.add(ts - fl.last_fwd)
            fl.fwd_n += 1
            fl.fwd_bytes += pv.incl_len
            fl.fwd_len.add(pv.incl_len)
            fl.fwd_hdr += pv.ip_hdr_len + pv.l4_hdr_len
            fl.last_fwd = ts
            if pv.proto == PROTO_TCP:
                fl.fwd_win.add(pv.win)
                if pv.tcp_flags & 0x08:
                    fl.fwd_psh += 1
                    fl.psh += 1
                if pv.tcp_flags & 0x20:
                    fl.fwd_urg += 1
                    fl.urg += 1
                if pv.tcp_flags & 0x01:
                    fl.fin += 1
                if pv.tcp_flags & 0x02:
                    fl.syn += 1
                if pv.tcp_flags & 0x04:
                    fl.rst += 1
                if pv.tcp_flags & 0x10:
                    fl.ack += 1
                if pv.tcp_flags & 0x40:
                    fl.ece += 1
                if pv.tcp_flags & 0x80:
                    fl.cwr += 1
            if pv.payload_len > 0:
                fl.fwd_data += 1
        else:
            if fl.bwd_n == 0 and pv.proto == PROTO_TCP:
                fl.init_bwd_win = pv.win
            if fl.bwd_n > 0:
                fl.bwd_iat.add(ts - fl.last_bwd)
            fl.bwd_n += 1
            fl.bwd_bytes += pv.incl_len
            fl.bwd_len.add(pv.incl_len)
            fl.bwd_hdr += pv.ip_hdr_len + pv.l4_hdr_len
            fl.last_bwd = ts
            if pv.proto == PROTO_TCP:
                fl.bwd_win.add(pv.win)
                if pv.tcp_flags & 0x08:
                    fl.bwd_psh += 1
                    fl.psh += 1
                if pv.tcp_flags & 0x20:
                    fl.bwd_urg += 1
                    fl.urg += 1
                if pv.tcp_flags & 0x01:
                    fl.fin += 1
                if pv.tcp_flags & 0x02:
                    fl.syn += 1
                if pv.tcp_flags & 0x04:
                    fl.rst += 1
                if pv.tcp_flags & 0x10:
                    fl.ack += 1
                if pv.tcp_flags & 0x40:
                    fl.ece += 1
                if pv.tcp_flags & 0x80:
                    fl.cwr += 1
            if pv.payload_len > 0:
                fl.bwd_data += 1
        fl.last = ts

    def _make_event(self, kind: str, window_sec: float, fl: Flow,
                    fwd_key: tuple, closed_at: float) -> FlowEvent:
        cols: dict[str, list] = {n: [] for n in FEATURE_NAMES}
        flow_to_row(fl, cols)
        row = {n: cols[n][0] for n in FEATURE_NAMES}
        meta = _flow_meta(fl.proto, fwd_key, fl)
        if self.metrics is not None:
            self.metrics.incr("flows_scored")
        return FlowEvent(
            kind=kind, window_sec=window_sec, row=row, flow_id=meta["flow_id"],
            src_ip=meta["src_ip"], dst_ip=meta["dst_ip"],
            src_port=meta["src_port"], dst_port=meta["dst_port"],
            proto=meta["proto"], start_ts=fl.start, end_ts=fl.last,
            n_packets=fl.fwd_n + fl.bwd_n, flow=fl,
        )
