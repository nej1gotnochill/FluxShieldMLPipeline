"""Detectors: common interface + the six threat detectors.

Rules enforced here:
  * every detector implements score(state) and returns DetectorResult;
  * detectors never write dashboard state; they only score and report;
  * a detector failure is contained by the service (degraded_mode), it can
    never crash the pipeline (DDoS keeps operating);
  * evidence comes from actually computed features only;
  * fingerprints that cannot be derived are reported as
    "fingerprint_unavailable" — never fabricated.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from typing import Any

from schema import AlertEvent, prediction_for
from state import TTLStateStore
from windows import FlowEvent
from pcap_source import PacketView

# ---------------------------------------------------------------------- #
# interface


@dataclass(slots=True)
class DetectorResult:
    threat_class: str
    score: float                 # detector-level score in [0, 1]
    confidence: float            # calibrated confidence in [0, 1]
    evidence: dict[str, Any]
    subtype: str = ""
    window_start: float = 0.0
    window_end: float = 0.0
    active: bool = False         # True only when the detector wants an alert


class BaseDetector:
    """Common abstraction: name, version, thresholds, score(state)."""
    name = "base"
    threat_class = "DDOS"
    version = "0.0"

    def __init__(self, *, suspicious_floor: float = 0.5, attack_floor: float = 0.8) -> None:
        self.suspicious_floor = float(suspicious_floor)
        self.attack_floor = float(attack_floor)
        self.status = "ok"          # ok | degraded
        self.last_error: str | None = None

    def score(self, state: Any) -> list[DetectorResult]:
        raise NotImplementedError

    def result(self, score: float, evidence: dict[str, Any], *,
               subtype: str = "", w_start: float = 0.0, w_end: float = 0.0,
               confidence: float | None = None) -> DetectorResult:
        conf = confidence if confidence is not None else score
        return DetectorResult(
            threat_class=self.threat_class, score=min(max(score, 0.0), 1.0),
            confidence=min(max(conf, 0.0), 1.0), evidence=evidence,
            subtype=subtype, window_start=w_start, window_end=w_end,
            active=score >= self.suspicious_floor,
        )

    # model_identity() is provided by the ModelIdentified mixin (do NOT
    # redefine it here: BaseDetector precedes the mixin in the MRO and a
    # stub here would shadow the real implementation).


class ModelIdentified:
    """Mixin giving detectors a model identity for the alert schema."""
    name = "base"
    version = "0.0"

    def model_identity(self, threshold: float):
        from schema import ModelIdentity
        return ModelIdentity(name=self.name, version=self.version, threshold=threshold)


# ---------------------------------------------------------------------- #
# cross-flow aggregation (Phase 2) — consumed by behavioural detectors

@dataclass(slots=True)
class SrcWindow:            # per (src_ip, window) state
    dst_ips: set = field(default_factory=set)
    dst_ports: set = field(default_factory=set)
    attempts: int = 0
    syn_only: int = 0
    rst_seen: int = 0
    flows: int = 0


@dataclass(slots=True)
class DstPairWindow:        # per (src, dst, dport-ish service, window) C2 state
    events: list = field(default_factory=list)     # timestamps (bounded)
    bytes_out: int = 0
    bytes_in: int = 0


@dataclass(slots=True)
class HostWindow:           # per (host, window) exfil state
    bytes_out: int = 0
    bytes_in: int = 0
    dst_ips: set = field(default_factory=set)
    out_flows: int = 0


@dataclass(slots=True)
class SrcMix:               # per-bucket source packet distribution (DDoS entropy)
    counts: dict = field(default_factory=dict)   # src_ip -> packets
    packets: int = 0


def _is_multicast_or_broadcast(ip: str) -> bool:
    """IPv4 multicast (224.0.0.0/4) or broadcast (last octet 255)."""
    try:
        o = [int(x) for x in ip.split(".")]
        return len(o) == 4 and (224 <= o[0] <= 239 or o[3] == 255)
    except (ValueError, AttributeError):
        return False


def flows_dense(fanout: int, flows: int) -> bool:
    """True when a fan-out dimension is saturated by real traffic (>= 5 flows
    per fan-out unit) — usage, not scanning."""
    return flows >= 5 * max(fanout, 1)


class Aggregator:
    """Bounded cross-flow state on top of TTLStateStore.

    consume(FlowEvent) folds flow closures into per-window aggregates; the
    behavioural detectors score the aggregates when a window rolls over.
    """

    def __init__(self, store: TTLStateStore, window_sec: float = 10.0) -> None:
        self.store = store
        self.window_sec = window_sec
        self.current_bucket: float | None = None

    def bucket_of(self, ts: float) -> float:
        return math.floor(ts / self.window_sec) * self.window_sec

    def consume(self, fe: FlowEvent, now: float | None = None) -> None:
        b = self.bucket_of(fe.end_ts if fe.end_ts else fe.start_ts)
        self.current_bucket = max(self.current_bucket or b, b)
        # ---- recon: per (src, bucket) fan-out ----
        def _u(src_w: SrcWindow) -> SrcWindow:
            src_w.dst_ips.add(fe.dst_ip)
            src_w.dst_ports.add(fe.dst_port)
            src_w.flows += 1
            src_w.attempts += fe.n_packets
            fl = fe.flow
            if fl is not None and fe.proto == "TCP":
                if fl.syn > 0 and fl.ack == 0:
                    src_w.syn_only += 1
                if fl.rst > 0:
                    src_w.rst_seen += 1
            return src_w
        self.store.update("recon", (fe.src_ip, b), _u, SrcWindow)
        # ---- C2: long-lived per-(src, dst) event series (TTL 900 s).
        # Beacon periods (30-60 s) far exceed one aggregation bucket, so the
        # series must NOT be per-bucket: it accumulates across buckets and is
        # pruned on read. Bounded to 256 events per pair.
        # Multicast/broadcast destinations are excluded: infrastructure
        # protocols (OSPF hellos to 224.0.0.5 every 10 s, VRRP, etc.) are
        # perfectly periodic low-rate 'beacons' and would otherwise dominate
        # the C2 alert stream. C2 beaconing targets unicast servers.
        if not _is_multicast_or_broadcast(fe.dst_ip):
            def _u2(pw: DstPairWindow) -> DstPairWindow:
                if len(pw.events) < 256:
                    pw.events.append(fe.start_ts)
                pw.bytes_out += int(fe.row["fwd_bytes"])
                pw.bytes_in += int(fe.row["bwd_bytes"])
                return pw
            self.store.update("c2pair", (fe.src_ip, fe.dst_ip), _u2, DstPairWindow,
                              ttl_sec=900.0)
        # ---- exfil: per (src, bucket) host view ----
        def _u3(hw: HostWindow) -> HostWindow:
            hw.bytes_out += int(fe.row["fwd_bytes"])
            hw.bytes_in += int(fe.row["bwd_bytes"])
            hw.dst_ips.add(fe.dst_ip)
            hw.out_flows += 1
            return hw
        self.store.update("exfil", (fe.src_ip, b), _u3, HostWindow)
        # ---- DDoS entropy: per-bucket source packet distribution (bounded:
        # per-bucket entry, pruned with the bucket) — feeds source-IP
        # entropy evidence required by the brief's volumetric class.
        # Window-kind closures only: terminal closures re-count the same
        # packets (they are the lagged counterpart of window closures),
        # which would distort the distribution.
        if fe.kind == "window":
            def _u4(mix: SrcMix) -> SrcMix:
                mix.counts[fe.src_ip] = mix.counts.get(fe.src_ip, 0) + fe.n_packets
                mix.packets += fe.n_packets
                return mix
            self.store.update("srcmix", b, _u4, SrcMix, ttl_sec=self.window_sec * 3)

    def roll_window(self) -> float | None:
        """Return and advance the completed bucket, if one is complete."""
        if self.current_bucket is None:
            return None
        return self.current_bucket - self.window_sec

    def source_mix_stats(self, bucket: float) -> dict | None:
        """Source-IP entropy statistics for one aggregation bucket.

        Shannon entropy (bits) over the per-source packet distribution plus
        uniqueness/concentration — the volumetric-class evidence the brief
        names explicitly (spoofed floods spread packets across many source
        addresses, driving entropy up while staying concentrated by bytes)."""
        mix = self.store.get("srcmix", bucket)
        if not mix or mix.packets <= 0 or not mix.counts:
            return None
        n = mix.packets
        ent = 0.0
        for c in mix.counts.values():
            if c > 0:
                p = c / n
                ent -= p * math.log2(p)
        top_src, top_c = max(mix.counts.items(), key=lambda kv: kv[1])
        return {
            "src_ip_entropy_bits": round(ent, 4),
            "max_entropy_bits": round(math.log2(len(mix.counts)), 4) if len(mix.counts) > 1 else 0.0,
            "unique_source_ips": len(mix.counts),
            "bucket_packets": n,
            "top_source": top_src,
            "top_source_packet_share": round(top_c / n, 4),
        }


# ---------------------------------------------------------------------- #
# CLASS 1 — DDoS (frozen model, flow/rate based; untouched artifacts)

class FrozenDDoSDetector(BaseDetector, ModelIdentified):
    """Scores closed flow rows with the existing calibrated ExtraTrees.

    The 66-feature contract, calibration and threshold are untouched. Family
    attribution in `subtype` is an evidence heuristic (flag/rate composition),
    NOT a second model — stated as such in the evidence dict.
    """
    name = "ddos-frozen-et"
    threat_class = "DDOS"
    version = "1.0"

    def __init__(self, model, threshold: float, feature_names: list[str], **kw) -> None:
        super().__init__(**kw)
        self.model = model
        self.threshold = float(threshold)
        self.features = feature_names

    # -- batch scoring (micro-batch, vectorized) ----------------------- #
    def score_rows(self, rows: list[dict[str, float]]) -> list[DetectorResult]:
        if not rows:
            return []
        import numpy as np
        x = np.asarray([[float(r[f]) for f in self.features] for r in rows],
                       dtype=np.float32)
        probas = self.model.predict_proba(x)[:, 1]
        out: list[DetectorResult] = []
        for row, p in zip(rows, probas):
            p = float(p)
            ev = self._evidence(row)
            res = self.result(
                p, ev, subtype=self._subtype(row),
                w_start=float(row.get("flow_duration_s", 0.0)),
                confidence=p,
            )
            # alert only at the calibrated operating threshold
            res.active = p >= self.threshold
            out.append(res)
        return out

    # compatibility with the BaseDetector interface
    def score(self, state):
        return self.score_rows([state]) if isinstance(state, dict) else []

    def _evidence(self, r: dict[str, float]) -> dict[str, Any]:
        n = max(r.get("fwd_packets", 0.0) + r.get("bwd_packets", 0.0), 1.0)
        dur = max(r.get("flow_duration_s", 0.0), 1e-6)
        return {
            "packets_per_sec": round(n / dur, 2),
            "bytes_per_sec": round((r.get("fwd_bytes", 0.0) + r.get("bwd_bytes", 0.0)) / dur, 2),
            "fwd_packets": r.get("fwd_packets", 0.0),
            "bwd_packets": r.get("bwd_packets", 0.0),
            "syn_count": r.get("syn_count", 0.0),
            "rst_count": r.get("rst_count", 0.0),
            "attack_probability": None,   # filled by service after scoring
            "family_attribution": "heuristic_flag_composition",
        }

    def _subtype(self, r: dict[str, float]) -> str:
        syn = r.get("syn_count", 0.0)
        rst = r.get("rst_count", 0.0)
        proto = r.get("protocol", 0.0)
        pps = r.get("flow_packets_s", 0.0)
        if syn >= 2 and rst == 0:
            return "TCP_SYN_FLOOD"
        if rst >= 2:
            return "TCP_RST_FLOOD"
        if proto == 17.0 and pps > 100:
            return "UDP_FLOOD"
        if pps > 1000:
            return "VOLUMETRIC"
        return "DDOS_GENERIC"


# ---------------------------------------------------------------------- #
# CLASS 2 — C2 beaconing (temporal, per source-destination pair)

class C2BeaconDetector(BaseDetector, ModelIdentified):
    name = "c2-periodicity"
    threat_class = "C2"
    version = "1.0"

    def __init__(self, *, min_events: int = 6, cv_strong: float = 0.35,
                 cv_weak: float = 0.65, min_interval_sec: float = 1.0,
                 max_pair_rate: float = 0.5, **kw) -> None:
        super().__init__(**kw)
        self.min_events = min_events
        self.cv_strong = cv_strong
        self.cv_weak = cv_weak
        self.min_interval_sec = min_interval_sec
        self.max_pair_rate = max_pair_rate

    def score_pair(self, src: str, dst: str, events: list[float]) -> DetectorResult | None:
        if len(events) < self.min_events:
            return None
        ts = sorted(events)
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if len(gaps) < self.min_events - 1:
            return None
        mean = sum(gaps) / len(gaps)
        # Flood/chatter gates: beaconing is LOW-RATE repetition (typical
        # periods are tens of seconds to minutes). Sub-second mean intervals
        # are volumetric territory (DDoS detector's job), and so are high
        # flow rates per pair: a SYN flood toward one destination closes
        # hundreds of flows per second and its closure-time series can
        # otherwise masquerade as a perfect beacon.
        if mean < self.min_interval_sec:
            return None
        span0 = ts[-1] - ts[0]
        if span0 > 0 and len(events) / span0 > self.max_pair_rate:
            return None
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        cv = math.sqrt(var) / mean if mean > 0 else 1e9
        span = ts[-1] - ts[0]
        rate = len(events) / span if span > 0 else 0.0
        # periodicity score: low CV + sustained low-rate repetition
        cv_score = 1.0 if cv <= self.cv_strong else \
            max(0.0, (self.cv_weak - cv) / (self.cv_weak - self.cv_strong)) \
            if cv < self.cv_weak else 0.0
        sustain = min(1.0, len(events) / (self.min_events * 2))
        score = 0.7 * cv_score + 0.3 * sustain
        if score < self.suspicious_floor:
            return None
        state = "LIKELY_BEACON" if score >= self.attack_floor else "SUSPICIOUS"
        return self.result(
            score,
            {
                "state": state,
                "events": len(events),
                "mean_interval_sec": round(mean, 3),
                "interval_cv": round(cv, 4),
                "beacon_interval_stability": round(cv_score, 3),
                "events_per_sec": round(rate, 4),
                "src": src, "dst": dst,
                "note": "temporal pattern over repeated flows; no payload inspected",
            },
            subtype=state,
            w_start=ts[0], w_end=ts[-1],
        )

    def score(self, state) -> list[DetectorResult]:
        return []


# ---------------------------------------------------------------------- #
# CLASS 3 — DNS: DGA + tunneling (metadata only)

class DNSMetaExtractor:
    """Parses header-grade DNS query metadata from UDP/53 payload slices.

    Only structure (names, lengths, types) — never payload contents beyond
    the DNS question itself, which is metadata by the brief's definition.
    """

    def __init__(self) -> None:
        self.recent: list[dict[str, Any]] = []      # bounded per service tick
        self.cap = 2048

    def observe(self, pv: PacketView) -> None:
        if pv.proto != 17 or pv.dport != 53 or len(pv.payload) < 20:
            return
        p = pv.payload
        qdcount = (p[4] << 8) | p[5]
        if qdcount < 1:
            return
        off = 12
        labels = []
        try:
            while off < len(p):
                ln = p[off]
                if ln == 0:
                    off += 1
                    break
                if ln & 0xC0 or off + 1 + ln > len(p):
                    return                    # compression/overflow: skip packet
                labels.append(p[off + 1:off + 1 + ln])
                off += 1 + ln
            if not labels:
                return
            qtype = ((p[off]) << 8) | p[off + 1] if off + 2 <= len(p) else 0
        except IndexError:
            return
        name = ".".join(l.decode("latin-1", "replace") for l in labels)
        registrable = ".".join(l.decode("latin-1", "replace") for l in labels[-2:]) \
            if len(labels) >= 2 else name
        self.recent.append({
            "ts": pv.ts, "qname": name, "registrable": registrable,
            "qlen": len(name), "n_labels": len(labels),
            "max_label": max(len(l) for l in labels),
            "entropy": _shannon(name),
            "digit_ratio": sum(c.isdigit() for c in name) / max(len(name), 1),
            "qtype": qtype,
            "src": PacketView_src(pv),
        })
        if len(self.recent) > self.cap:
            del self.recent[: len(self.recent) - self.cap]

    def drain(self) -> list[dict[str, Any]]:
        out, self.recent = self.recent, []
        return out


def PacketView_src(pv: PacketView) -> str:
    from pcap_source import src_str
    return src_str(pv.src_b)


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


class DNSDetector(BaseDetector, ModelIdentified):
    """DGA_SCORE and DNS_TUNNEL_SCORE from query-name metadata."""
    name = "dns-metadata"
    threat_class = "DGA"
    version = "1.0"

    def __init__(self, *, entropy_hi: float = 3.8, qlen_hi: int = 45,
                 maxlabel_hi: int = 25, tunnel_qlen: int = 60,
                 min_queries: int = 5, **kw) -> None:
        super().__init__(**kw)
        self.entropy_hi = entropy_hi
        self.qlen_hi = qlen_hi
        self.maxlabel_hi = maxlabel_hi
        self.tunnel_qlen = tunnel_qlen
        self.min_queries = min_queries

    def score_queries(self, queries: list[dict[str, Any]]) -> list[DetectorResult]:
        out: list[DetectorResult] = []
        if not queries:
            return out
        by_domain: dict[str, list[dict[str, Any]]] = {}
        for q in queries:
            by_domain.setdefault(q["registrable"], []).append(q)
        for dom, qs in by_domain.items():
            if len(qs) < self.min_queries:
                continue
            ents = [q["entropy"] for q in qs]
            lens = [q["qlen"] for q in qs]
            maxlab = max(q["max_label"] for q in qs)
            uniq = len({q["qname"] for q in qs})
            mean_ent = sum(ents) / len(ents)
            mean_len = sum(lens) / len(lens)
            src = qs[0]["src"]
            # DGA: many unique, high-entropy names under one registrable domain
            dga = min(1.0, max(0.0,
                     0.5 * (mean_ent / 4.5) + 0.3 * (uniq / max(len(qs), 1))
                     + 0.2 * (1.0 if mean_len > self.qlen_hi else 0.0)))
            # tunneling: very long names / huge labels / TXT-heavy repetition
            txt_ratio = sum(1 for q in qs if q["qtype"] == 16) / len(qs)
            tun = min(1.0, max(0.0,
                     0.45 * (mean_len / self.tunnel_qlen)
                     + 0.35 * (1.0 if maxlab >= self.maxlabel_hi else maxlab / self.maxlabel_hi)
                     + 0.2 * txt_ratio))
            if dga >= self.suspicious_floor:
                out.append(self.result(dga, {
                    "domain": dom, "queries": len(qs), "unique_names": uniq,
                    "mean_entropy": round(mean_ent, 3), "mean_query_length": round(mean_len, 1),
                    "digit_ratio": round(sum(q["digit_ratio"] for q in qs) / len(qs), 3),
                    "src": src, "method": "entropy+ngram-composition (rule, DATA-LIMITED)",
                }, subtype="DGA_DOMAIN", w_start=qs[0]["ts"], w_end=qs[-1]["ts"]))
            if tun >= self.suspicious_floor:
                out.append(DetectorResult(
                    threat_class="DGA", score=tun, confidence=tun,
                    evidence={
                        "domain": dom, "queries": len(qs),
                        "max_label_len": maxlab, "mean_query_length": round(mean_len, 1),
                        "txt_ratio": round(txt_ratio, 3), "src": src,
                        "method": "query-length/label/record-type (rule, DATA-LIMITED)",
                    },
                    subtype="DNS_TUNNEL", window_start=qs[0]["ts"],
                    window_end=qs[-1]["ts"], active=tun >= self.suspicious_floor,
                ))
        return out

    def score(self, state):
        return []


# ---------------------------------------------------------------------- #
# CLASS 4 — encrypted-session metadata (TLS client fingerprint, no decryption)

class TLSMetaDetector(BaseDetector, ModelIdentified):
    """JA3-style client fingerprint from TLS ClientHello headers.

    Reads only the handshake header bytes (version, cipher list, extensions)
    that are transmitted in cleartext. Nothing is decrypted; when the capture
    does not expose a ClientHello the result says fingerprint_unavailable.
    """
    name = "tls-metadata"
    threat_class = "ENCRYPTED_MALWARE"
    version = "1.0"

    def __init__(self, *, min_sessions: int = 3, **kw) -> None:
        super().__init__(**kw)
        self.min_sessions = min_sessions
        self.sessions: dict[str, list[dict[str, Any]]] = {}

    def observe(self, pv: PacketView) -> None:
        if pv.proto != 6 or len(pv.payload) < 6:
            return
        p = pv.payload
        if p[0] != 0x16 or p[1] != 0x03:        # not a TLS handshake record
            return
        if p[5] != 0x01:                        # not ClientHello
            return
        try:
            ver = f"{p[9]}.{p[10]}"
            # ClientHello body (after 5B record hdr + 4B handshake hdr):
            #   2B version | 32B random | 1B sid_len | sid | 2B cs_len |
            #   ciphers | 1B comp_len | comp | 2B ext_len | extensions
            base = 9 + 2 + 32
            sid_len = p[base]
            off = base + 1 + sid_len
            cs_len = p[off + 1] | (p[off] << 8)
            ciphers = p[off + 2:off + 2 + cs_len]
            off += 2 + cs_len
            if off >= len(p):
                raise IndexError
            comp_len = p[off]
            off += 1 + comp_len
            ext_len = p[off + 1] | (p[off] << 8) if off + 2 <= len(p) else 0
            ja3 = f"{ver},{ciphers.hex().upper()},{int(ext_len)}"
            fp = hashlib.md5(ja3.encode()).hexdigest()
        except (IndexError, ValueError):
            fp = "fingerprint_unavailable"
            ja3 = ""
        key = pv.src_b.hex()
        self.sessions.setdefault(key, []).append({
            "ts": pv.ts, "src": PacketView_src(pv), "dst": pv.dst_b.hex(),
            "dst_port": pv.dport, "ja3": fp, "ja3_material": ja3,
            "tls_version": ver if 'ver' in dir() else "unknown",
        })
        if len(self.sessions[key]) > 256:
            del self.sessions[key][:128]

    def drain(self) -> list[DetectorResult]:
        out: list[DetectorResult] = []
        now = time.time()
        for key, sess in list(self.sessions.items()):
            if len(sess) < self.min_sessions:
                continue
            fps = [s["ja3"] for s in sess]
            uniq = len(set(fps))
            avail = [f for f in fps if f != "fingerprint_unavailable"]
            ev = {
                "sessions": len(sess),
                "unique_fingerprints": uniq,
                "fingerprint_available": bool(avail),
                "fingerprint": avail[0] if len(set(avail)) == 1 and avail
                else ("fingerprint_unavailable" if not avail else f"{len(set(avail))} distinct"),
                "dst_ports": sorted({s["dst_port"] for s in sess})[:8],
                "note": "handshake metadata only; no decryption performed",
            }
            # repetition of one fingerprint toward few destinations is the
            # observable; conservative two-level scoring (DATA-LIMITED):
            #   0.6 SUSPICIOUS — one repeated fingerprint, >= 2*min_sessions
            #   0.0 informational otherwise (surfaced for observability only)
            score = 0.6 if (avail and uniq == 1 and len(sess) >= 2 * self.min_sessions) else 0.0
            if len(sess) >= self.min_sessions:
                ev["method"] = "cleartext-handshake repetition (rule, DATA-LIMITED)"
                res = self.result(score, ev, subtype="TLS_CLIENT_REP",
                                  w_start=sess[0]["ts"], w_end=sess[-1]["ts"])
                res.active = score >= self.suspicious_floor
                out.append(res)
            if now - sess[-1]["ts"] > 600:
                del self.sessions[key]
        return out

    def score(self, state):
        return []


# ---------------------------------------------------------------------- #
# CLASS 5 — recon / port scanning (cross-flow fan-out)

class ReconDetector(BaseDetector, ModelIdentified):
    name = "recon-fanout"
    threat_class = "RECON"
    version = "1.0"

    def __init__(self, *, port_fanout: int = 12, host_fanout: int = 8,
                 min_flows: int = 10, **kw) -> None:
        super().__init__(**kw)
        self.port_fanout = port_fanout
        self.host_fanout = host_fanout
        self.min_flows = min_flows

    def score_src(self, src: str, sw: SrcWindow, bucket: float,
                  window_sec: float) -> DetectorResult | None:
        if sw.flows < self.min_flows:
            return None
        ports, hosts = len(sw.dst_ports), len(sw.dst_ips)
        syn_ratio = sw.syn_only / max(sw.flows, 1)
        rst_ratio = sw.rst_seen / max(sw.flows, 1)
        # Flow-density gate: a scanner sends ~1 flow per port/host; a busy
        # legitimate client sends many flows to each. A fan-out dimension
        # saturated by real traffic (flows >= 5x the fan-out) is usage, not
        # scanning, and contributes no score.
        port_component = ports / (self.port_fanout * 4) if flows_dense(ports, sw.flows) else 0.0
        host_component = hosts / (self.host_fanout * 4) if flows_dense(hosts, sw.flows) else 0.0
        score = min(1.0, max(
            port_component,
            host_component,
            0.55 if (syn_ratio > 0.8 and ports >= self.port_fanout) else 0.0,
        ))
        if score < self.suspicious_floor:
            return None
        if ports >= self.port_fanout and hosts <= 2:
            rtype = "PORT_SCAN"
        elif hosts >= self.host_fanout and ports <= 4:
            rtype = "HOST_SCAN"
        else:
            rtype = "SERVICE_DISCOVERY"
        return self.result(score, {
            "unique_ports": ports, "unique_hosts": hosts,
            "flows": sw.flows, "syn_only_flows": sw.syn_only,
            "syn_ratio": round(syn_ratio, 3), "rst_ratio": round(rst_ratio, 3),
            "recon_type": rtype, "src": src,
            "method": "fan-out aggregation (rule, calibrated on fixture data)",
        }, subtype=rtype, w_start=bucket, w_end=bucket + window_sec)


# ---------------------------------------------------------------------- #
# CLASS 6 — exfiltration (directional volume behaviour)

class ExfilDetector(BaseDetector, ModelIdentified):
    name = "exfil-directional"
    threat_class = "EXFIL"
    version = "1.0"

    def __init__(self, *, out_ratio: float = 8.0, min_bytes_out: int = 5_000_000,
                 min_dst: int = 3, **kw) -> None:
        super().__init__(**kw)
        self.out_ratio = out_ratio
        self.min_bytes_out = min_bytes_out
        self.min_dst = min_dst

    def score_host(self, host: str, hw: HostWindow, bucket: float,
                   window_sec: float) -> DetectorResult | None:
        if hw.bytes_out < self.min_bytes_out:
            return None                      # behavioural baseline: ignore small transfers
        ratio = hw.bytes_out / max(hw.bytes_in, 1)
        dst_uniq = len(hw.dst_ips)
        # Behavioral baselining (brief: never label every high-volume outbound
        # flow as exfiltration). Asymmetry ALONE is normal (web/DNS servers,
        # download clients); exfiltration requires asymmetry AND destination
        # diversity (rarity). Single-destination asymmetry is informational 0.
        if ratio < self.out_ratio or dst_uniq < self.min_dst:
            return None
        score = min(1.0, 0.5 + 0.5 * min(ratio / (self.out_ratio * 4), 1.0))
        if score < self.suspicious_floor:
            return None
        return self.result(score, {
            "bytes_out": hw.bytes_out, "bytes_in": hw.bytes_in,
            "outbound_ratio": round(ratio, 2), "unique_destinations": dst_uniq,
            "outbound_flows": hw.out_flows, "host": host,
            "method": "directional ratio + destination rarity (rule, baseline-gated)",
        }, subtype="OUTBOUND_ASYMMETRY", w_start=bucket, w_end=bucket + window_sec)
