"""End-to-end streaming service: the real INGEST -> WINDOW -> SCORE -> ALERT loop.

Pipeline per packet (all read-only, passive):
    PcapPacketSource -> StreamingFlowEngine (causal windows + terminal flows)
                     -> Aggregator (cross-flow state)
                     -> DNS/TLS metadata observers (header-grade only)
                     -> DetectorRegistry (per-threat, failure-isolated)
                     -> ThreatFusion -> AlertEvent -> BoundedEventBus
                     -> dashboard emitter (LIVE mode)

Failure isolation: every detector invocation is wrapped; a raising detector
sets its status to "degraded", increments metrics.detector_errors, and the
loop continues. The DDoS detector is additionally isolated from behavioural
detectors so it keeps operating if the aggregation layer fails.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from bus import BoundedEventBus
from detectors import (
    Aggregator, C2BeaconDetector, DNSDetector, DetectorResult,
    ExfilDetector, FrozenDDoSDetector, ReconDetector, TLSMetaDetector,
)
from fusion import ThreatFusion
from metrics import Metrics
from pcap_source import PcapPacketSource
from schema import AlertEvent, ModelIdentity
from state import TTLStateStore
from windows import FlowEvent, StreamingFlowEngine, WindowConfig


class StreamingService:
    def __init__(self, *, ddos_model=None, ddos_threshold: float = 0.5,
                 ddos_features: list[str] | None = None,
                 window_sec: float = 3.0, agg_window_sec: float = 10.0,
                 state_ttl_sec: float = 300.0, state_capacity: int = 100_000,
                 bus_size: int = 10_000, state: str = "LIVE",
                 exfil_min_bytes_out: int = 5_000_000,
                 fusion_cfg: dict[str, float] | None = None) -> None:
        self.metrics = Metrics()
        self.cfg = WindowConfig(window_sec=window_sec)
        self.engine = StreamingFlowEngine(self.cfg, self.metrics)
        self.store = TTLStateStore(ttl_sec=state_ttl_sec, capacity=state_capacity)
        self.agg = Aggregator(self.store, window_sec=agg_window_sec)
        self.bus = BoundedEventBus(maxsize=bus_size)
        self.state_label = state
        self.fusion = ThreatFusion(**(fusion_cfg or {}))
        self.registry: dict[str, Any] = {}
        if ddos_model is not None:
            self.registry["ddos"] = FrozenDDoSDetector(
                ddos_model, ddos_threshold, ddos_features)
        self.registry["recon"] = ReconDetector()
        self.registry["c2"] = C2BeaconDetector()
        self.registry["dns"] = DNSDetector()
        self.registry["tls"] = TLSMetaDetector()
        self.registry["exfil"] = ExfilDetector(min_bytes_out=exfil_min_bytes_out)
        self.dns_extractor = None      # (unused placeholder ref; kept explicit)
        from detectors import DNSMetaExtractor
        self.dns_obs = DNSMetaExtractor()
        self.tls_obs = self.registry["tls"]
        self._last_roll: float | None = None
        self._window_flow_index: dict[tuple, list[FlowEvent]] = {}
        self._c2_last_alert: dict[str, float] = {}
        self.C2_ALERT_COOLDOWN_SEC = 60.0
        self._ddos_buffer: list[FlowEvent] = []
        self._pkts_since_flush = 0
        self.DDOS_BATCH_ROWS = 1_024
        self.DDOS_FLUSH_EVERY = 5_000
        self._ddos_last_alert: dict[tuple, float] = {}
        self.DDOS_ALERT_COOLDOWN_SEC = 60.0

    # ------------------------------------------------------------------ #
    def process_packet(self, pv) -> list[AlertEvent]:
        t0 = time.perf_counter()
        self.metrics.incr("events_received")
        self.metrics.incr("packets_parsed")
        self._pkts_since_flush += 1
        alerts: list[AlertEvent] = []

        # 1. flow state (window + terminal closures)
        flow_events = self.engine.on_packet(pv)
        # 2. L7 metadata observers (DNS/TLS: header-grade only; call-site
        # gates so non-matching traffic never pays a function call)
        if pv.proto == 17 and pv.dport == 53:
            self.dns_obs.observe(pv)
        elif pv.proto == 6 and pv.dport == 443:
            self.tls_obs.observe(pv)
        # 3. cross-flow aggregation from ALL closed flows (window closures
        # included: a frozen window row is real observed traffic; waiting for
        # terminal timeouts would starve short/quiet captures)
        for fe in flow_events:
            self._index_flow(fe)
            try:
                self.agg.consume(fe, pv.ts)
            except Exception:
                pass  # aggregation failure must not break flow scoring

        # 4. buffer closed flows for DDoS micro-batch scoring (per-packet
        # sklearn calls would dominate latency at line rate)
        fresh = list(flow_events)
        self._ddos_buffer.extend(fresh)
        if "ddos" in self.registry and (
                len(self._ddos_buffer) >= self.DDOS_BATCH_ROWS
                or self._pkts_since_flush >= self.DDOS_FLUSH_EVERY):
            self._flush_ddos_buffer()

        # 5. behavioural detectors on window rollover
        bucket = self.agg.current_bucket
        if bucket is not None and (self._last_roll is None or bucket > self._last_roll):
            if self._last_roll is not None:
                alerts += self._roll_behavioural(bucket)
            self._last_roll = bucket

        # 6. alerts for this packet are emitted by _flush_ddos_buffer (bus)
        # and by _roll_behavioural; the returned list is best-effort inline.

        # 7. emit + latency accounting
        for a in alerts:
            t2 = time.perf_counter()
            ok = self.bus.put(a)
            self.metrics.stage("alert_emit", time.perf_counter() - t2)
            if ok:
                self.metrics.incr("alerts_emitted")
            else:
                self.metrics.incr("alerts_dropped")
        self.metrics.stage("end_to_end", time.perf_counter() - t0)
        self.metrics.observe_queue(self.bus.depth())
        self.metrics.observe_state(self.store.size())
        return alerts

    # ------------------------------------------------------------------ #
    # ------------------------------------------------------------------ #
    def _flush_ddos_buffer(self) -> None:
        """Score buffered closed flows with the frozen DDoS model in one
        vectorized call, then AGGREGATE active flows per (source, subtype,
        bucket) into one alert each. A volumetric flood of N flows produces
        one alert with evidence {flows: N, ...} — per-flow alerting at flood
        rates would be unshippable noise (10k alerts/50k packets measured).
        """
        if not self._ddos_buffer:
            return
        if "ddos" not in self.registry:
            self._ddos_buffer.clear()
            return
        ddos = self.registry["ddos"]
        try:
            t1 = time.perf_counter()
            results = ddos.score_rows([fe.row for fe in self._ddos_buffer])
            self.metrics.stage("detector", time.perf_counter() - t1)
            groups: dict[tuple, list] = {}
            for fe, res in zip(self._ddos_buffer, results):
                fe.ddos_result = res
                if res.active:
                    bucket = self.agg.bucket_of(fe.end_ts or fe.start_ts)
                    groups.setdefault((fe.src_ip, res.subtype, bucket), []).append((fe, res))
            for (src, subtype, bucket), pairs in groups.items():
                # per-(source, subtype) alert cooldown: an ongoing flood must
                # not emit one alert per bucket per source; the cooldown
                # bounds volume while the evidence carries the current window
                last = self._ddos_last_alert.get((src, subtype), 0.0)
                bucket_end = bucket + self.agg.window_sec
                if bucket_end - last < self.DDOS_ALERT_COOLDOWN_SEC:
                    continue
                self._ddos_last_alert[(src, subtype)] = bucket_end
                fe0, res0 = pairs[0]
                probas = [r.score for _f, r in pairs]
                n_pkts = sum(f.n_packets for f, _ in pairs)
                n_bytes = sum(int(f.row.get("fwd_bytes", 0.0)) + int(f.row.get("bwd_bytes", 0.0))
                              for f, _ in pairs)
                dur = max((f.end_ts - f.start_ts for f, _ in pairs), default=0.0)
                evidence = dict(res0.evidence)
                evidence.update({
                    "aggregated_flows": len(pairs),
                    "max_attack_probability": round(max(probas), 4),
                    "mean_attack_probability": round(sum(probas) / len(probas), 4),
                    "aggregated_packets": n_pkts,
                    "aggregated_bytes": n_bytes,
                    "window_start": min(f.start_ts for f, _ in pairs),
                    "window_end": max(f.end_ts for f, _ in pairs),
                    "window_span_sec": round(dur, 3),
                })
                evidence["attack_probability"] = evidence["max_attack_probability"]
                a = self.fusion.to_alert(
                    {"threat_class": res0.threat_class, "subtype": subtype,
                     "confidence": max(r.confidence for _f, r in pairs),
                     "risk": max(r.score for _f, r in pairs),
                     "secondary": [],
                     "evidence": {res0.threat_class: evidence},
                     "window_start": evidence["window_start"],
                     "window_end": evidence["window_end"]},
                    flow_id=fe0.flow_id, src=fe0.src_ip, dst=fe0.dst_ip,
                    sport=fe0.src_port, dport=fe0.dst_port, proto=fe0.proto,
                    timestamp=AlertEvent.now_ts(),
                    window_sec=fe0.window_sec or self.cfg.window_sec,
                    model=ddos.model_identity(ddos.threshold),
                    latency_ms=0.0, state=self.state_label)
                if self.bus.put(a):
                    self.metrics.incr("alerts_emitted")
                else:
                    self.metrics.incr("alerts_dropped")
                self.metrics.incr("ddos_groups_aggregated")
        except Exception as e:
            ddos.status = "degraded"
            ddos.last_error = str(e)
            self.metrics.incr("detector_errors")
            self.metrics.incr("degraded_mode")
        finally:
            self._ddos_buffer.clear()
            self._pkts_since_flush = 0

    def _to_alert(self, res, fe, *, timestamp: str, model) -> AlertEvent:
        """DetectorResult + FlowEvent -> fused AlertEvent (DDoS path)."""
        evidence = dict(res.evidence)
        evidence["attack_probability"] = round(res.score, 4)
        fused = {
            "threat_class": res.threat_class,
            "subtype": res.subtype or res.threat_class,
            "confidence": res.confidence,
            "risk": res.score,
            "secondary": [],
            "evidence": {res.threat_class: evidence},
            "window_start": fe.start_ts,
            "window_end": fe.end_ts,
        }
        return self.fusion.to_alert(
            fused, flow_id=fe.flow_id, src=fe.src_ip, dst=fe.dst_ip,
            sport=fe.src_port, dport=fe.dst_port, proto=fe.proto,
            timestamp=timestamp,
            window_sec=fe.window_sec or self.cfg.window_sec,
            model=model, latency_ms=0.0, state=self.state_label)

    def _index_flow(self, fe) -> None:
        """Keep per-(src,bucket) FlowEvents for the DDoS-family aggregation and
        evidence; bounded by the state store TTL/capacity."""
        b = self.agg.bucket_of(fe.end_ts or fe.start_ts)
        key = (fe.src_ip, b)
        lst = self._window_flow_index.get(key)
        if lst is None:
            lst = []
            self._window_flow_index[key] = lst
        lst.append(fe)
        if len(lst) > 512:
            del lst[:256]

    def _roll_behavioural(self, bucket: float, *, flush: bool = False) -> list[AlertEvent]:
        """Score aggregates for the JUST-completed bucket (or everything on
        final flush) and emit alerts."""
        out: list[AlertEvent] = []
        prev = bucket - self.agg.window_sec
        now_ts = AlertEvent.now_ts()
        w = self.agg.window_sec
        results_by_entity: dict[str, list] = {}

        # --- recon: per source fan-out ---
        recon = self.registry["recon"]
        for (src, b), sw in list(self.store.items("recon")):
            if not flush and b != prev:
                continue
            r = _safe(lambda: recon.score_src(src, sw, b, w), recon, self.metrics)
            if r is not None:
                results_by_entity.setdefault(src, []).append(r)

        # --- C2: long-lived per-pair series, scored on every roll with
        # per-(entity) alert dedup (a beacon fires once per COOLDOWN, not
        # once per bucket) ---
        c2 = self.registry["c2"]
        for (src, dst), pw in list(self.store.items("c2pair")):
            if len(pw.events) < c2.min_events:
                continue
            r = _safe(lambda: c2.score_pair(src, dst, pw.events), c2, self.metrics)
            if r is None:
                continue
            entity = f"{src}->{dst}"
            last = self._c2_last_alert.get(entity, 0.0)
            if r.window_end - last < self.C2_ALERT_COOLDOWN_SEC:
                continue                      # still inside cooldown
            self._c2_last_alert[entity] = r.window_end
            results_by_entity.setdefault(entity, []).append(r)

        # --- DNS: drained query buffer ---
        dns = self.registry["dns"]
        for r in _safe(lambda: dns.score_queries(self.dns_obs.drain()), dns, self.metrics) or []:
            results_by_entity.setdefault(r.evidence.get("src", "?"), []).append(r)

        # --- TLS: drained session summaries ---
        tls = self.registry["tls"]
        for r in _safe(lambda: tls.drain(), tls, self.metrics) or []:
            results_by_entity.setdefault(r.evidence.get("dst", "?"), []).append(r)

        # --- exfil: per host directional volumes ---
        exfil = self.registry["exfil"]
        for (host, b), hw in list(self.store.items("exfil")):
            if not flush and b != prev:
                continue
            r = _safe(lambda: exfil.score_host(host, hw, b, w), exfil, self.metrics)
            if r is not None:
                results_by_entity.setdefault(host, []).append(r)

        # --- fusion per entity ---
        for entity, results in results_by_entity.items():
            hosts_flagged = len({e.split('->')[0] for e in results_by_entity})
            fused = _safe(lambda: self.fusion.fuse(
                results, entity=entity, hosts_flagged=hosts_flagged),
                self.fusion, self.metrics)
            if fused is None:
                continue
            fe = self._pick_flow(entity, prev)
            model = ModelIdentity(name=f"rule-{fused['threat_class'].lower()}",
                                  version="1.0", threshold=0.5)
            alert = _safe(lambda: self.fusion.to_alert(
                fused, flow_id=fe.flow_id if fe else entity,
                src=fe.src_ip if fe else entity.split('->')[0],
                dst=fe.dst_ip if fe else (entity.split('->')[-1] if '->' in entity else ""),
                sport=fe.src_port if fe else 0, dport=fe.dst_port if fe else 0,
                proto=fe.proto if fe else "TCP",
                timestamp=now_ts, window_sec=w,
                model=model, latency_ms=0.0, state=self.state_label),
                self.fusion, self.metrics)
            if alert is not None:
                out.append(alert)
        self.store.expire()
        return out

    def _pick_flow(self, entity: str, bucket: float):
        lst = self._window_flow_index.get((entity, bucket))
        return lst[-1] if lst else None

    # ------------------------------------------------------------------ #
    def run_pcap(self, path: str | Path, *, reaper_every_packets: int = 50_000) -> dict:
        """Consume one pcap read-only; returns the metrics snapshot."""
        t0 = time.perf_counter()
        for i, pv in enumerate(PcapPacketSource(path), 1):
            self.process_packet(pv)
            if i % reaper_every_packets == 0:
                for fe in self.engine.reap(pv.ts):
                    self._index_flow(fe)
        # EOF: flush remaining accumulators (parity with the offline
        # extractor's final flush), aggregate them, run one last roll + C2
        # pass so short captures still produce complete evidence.
        tail = self.engine.flush_all(pv.ts if i else 0.0)
        for fe in tail:
            self._index_flow(fe)
            try:
                self.agg.consume(fe, pv.ts if i else 0.0)
            except Exception:
                pass
        self._ddos_buffer.extend(tail)
        self._flush_ddos_buffer()
        for a in self._roll_behavioural(self.agg.current_bucket or 0.0, flush=True):
            if self.bus.put(a):
                self.metrics.incr("alerts_emitted")
            else:
                self.metrics.incr("alerts_dropped")
        snap = self.metrics.snapshot()
        snap["wall_sec"] = round(time.perf_counter() - t0, 3)
        snap["path"] = str(path)
        return snap

    def drain_alerts(self) -> list[AlertEvent]:
        return self.bus.drain()


def _safe(fn, det, metrics):
    try:
        return fn()
    except Exception as e:
        det.status = "degraded"
        det.last_error = str(e)
        metrics.incr("detector_errors")
        metrics.incr("degraded_mode")
        return None
