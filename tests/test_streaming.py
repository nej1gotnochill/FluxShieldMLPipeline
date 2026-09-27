"""Tests for the streaming layer (pytest, stdlib-only fixtures).

Covers the brief's testing requirements: alert schema, detector interface,
streaming windows, state expiration, DNS feature extraction, TLS metadata
extraction, beacon periodicity, scan aggregation, exfil aggregation, threat
fusion, live emitter, replay/live separation, and the end-to-end service
(packets -> features -> detector -> alert -> dashboard contract).

No dataset required: packets are synthesized ethernet/IPv4/TCP|UDP frames.
"""
from __future__ import annotations

import json
import socket
import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from src.streaming.schema import AlertEvent, ModelIdentity, prediction_for  # noqa: E402
from src.streaming.state import TTLStateStore                               # noqa: E402
from src.streaming.detectors import (                                       # noqa: E402
    Aggregator, C2BeaconDetector, DNSDetector, DNSMetaExtractor,
    ExfilDetector, ReconDetector, SrcWindow, TLSMetaDetector,
)
from src.streaming.fusion import ThreatFusion                               # noqa: E402
from src.streaming.emit import DashboardBridge                              # noqa: E402
from src.streaming.service import StreamingService                          # noqa: E402
from src.streaming.pcap_source import PcapPacketSource                      # noqa: E402


# ---------------------------------------------------------------------- #
# synthetic packet builders (read-only parse targets; no network involved)

def eth_ip_udp(src: str, dst: str, sport: int, dport: int,
               payload: bytes = b"", ts: float = 0.0) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + ip + udp


def eth_ip_tcp(src: str, dst: str, sport: int, dport: int, flags: int,
               win: int = 8192, payload: bytes = b"", ts: float = 0.0) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4, flags,
                      win, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + ip + tcp


def pcap_bytes(frames: list[tuple[float, bytes]], little: bool = True) -> bytes:
    magic = b"\x4d\x3c\xb2\xa1" if little else b"\xa1\xb2\x3c\x4d"
    # global header after magic: vmaj(H) vmin(H) thiszone(i) sigfigs(I) snaplen(I) network(I)
    gh = struct.pack("<HHiIII" if little else ">HHiIII", 2, 4, 0, 0, 65535, 1)
    out = magic + gh
    for ts, frame in frames:
        out += struct.pack("<IIII" if little else ">IIII",
                           int(ts), int(round((ts % 1) * 1e6)), len(frame), len(frame))
        out += frame
    return out


def write_pcap(path: Path, frames) -> str:
    path.write_bytes(pcap_bytes(list(frames)))
    return str(path)


def feed_frames(svc: StreamingService, frames):
    """Feed raw frames through a one-shot pcap so dedup/parser parity holds."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "t.pcap"
        write_pcap(p, frames)
        svc.run_pcap(p)


# ---------------------------------------------------------------------- #
# schema

def test_alert_schema_valid_and_roundtrip():
    a = AlertEvent(
        event_id="x", timestamp="2026-01-01T00:00:00.000+00:00", flow_id="f",
        source_ip="1.2.3.4", destination_ip="5.6.7.8", source_port=1,
        destination_port=2, protocol="TCP", threat_class="RECON",
        subtype="PORT_SCAN", prediction="ATTACK", confidence=0.9, risk=0.91,
        stage="RECON", technique="T1046", observation_window_sec=10.0,
        evidence={"unique_ports": 20}, model=ModelIdentity("recon", "1.0", 0.5),
        latency_ms=1.2,
    )
    d = a.to_dict()
    assert d["model"]["name"] == "recon" and d["evidence"]["unique_ports"] == 20
    assert json.loads(a.to_json())["threat_class"] == "RECON"


def test_alert_schema_rejects_bad_values():
    kw = dict(event_id="x", timestamp="t", flow_id="f", source_ip="a",
              destination_ip="b", source_port=0, destination_port=0,
              protocol="TCP", threat_class="DDOS", subtype="s",
              prediction="ATTACK", confidence=0.5, risk=0.5, stage="s",
              technique="t", observation_window_sec=1.0, evidence={"k": 1},
              model=ModelIdentity("m", "1", 0.5), latency_ms=0.0)
    with pytest.raises(ValueError):
        AlertEvent(**{**kw, "risk": 1.5})
    with pytest.raises(ValueError):
        AlertEvent(**{**kw, "threat_class": "NOT_A_CLASS"})
    with pytest.raises(ValueError):
        AlertEvent(**{**kw, "evidence": {}})
    with pytest.raises(ValueError):
        AlertEvent(**{**kw, "source_port": 70000})
    with pytest.raises(ValueError):
        AlertEvent(**{**kw, "confidence": float("nan")})


def test_prediction_mapping():
    assert prediction_for(0.9, 0.5, 0.8) == "ATTACK"
    assert prediction_for(0.6, 0.5, 0.8) == "SUSPICIOUS"
    assert prediction_for(0.1, 0.5, 0.8) == "BENIGN"


# ---------------------------------------------------------------------- #
# state store

def test_state_ttl_and_capacity():
    st = TTLStateStore(ttl_sec=10, capacity=3)
    st.set("ns", "a", 1, now=0)
    assert st.get("ns", "a", now=5) == 1
    assert st.get("ns", "a", now=11) is None          # expired (removed)
    for i in range(5):
        st.set("ns", f"k{i}", i, now=0)
    assert st.size("ns") == 3                          # capacity cap
    assert st.evicted == 2                              # k0, k1 evicted
    assert st.get("ns", "k0", now=0) is None
    assert st.get("ns", "k2", now=0) == 2 and st.get("ns", "k4", now=0) == 4


# ---------------------------------------------------------------------- #
# detectors

def test_recon_detector_fanout():
    d = ReconDetector()
    sw = SrcWindow()
    for p in range(1, 31):                 # 30 unique ports, 1 host
        sw.dst_ports.add(p)
        sw.dst_ips.add("10.0.0.9")
        sw.flows += 1
        sw.syn_only += 1
    r = d.score_src("1.1.1.1", sw, 0.0, 10.0)
    assert r is not None and r.active and r.subtype == "PORT_SCAN"
    assert r.evidence["unique_ports"] == 30
    assert r.score >= d.attack_floor or r.score >= d.suspicious_floor


def test_c2_detector_periodicity():
    d = C2BeaconDetector()
    events = [100.0 + i * 30.0 for i in range(12)]     # perfect 30 s beacon
    r = d.score_pair("s", "d", events)
    assert r is not None and r.active
    assert r.evidence["interval_cv"] < 0.05
    assert r.subtype == "LIKELY_BEACON"


def test_c2_detector_ignores_irregular():
    d = C2BeaconDetector()
    events = [100.0, 100.5, 190.0, 700.0, 701.2, 900.0, 1500.0]
    assert d.score_pair("s", "d", events) is None


def test_dns_extraction_and_dga():
    ex = DNSMetaExtractor()
    qname = b"\x04aval\x05x7h2q\x03com\x00"
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    ex.observe(type("PV", (), {"proto": 17, "dport": 53, "ts": 1.0,
                               "src_b": socket.inet_aton("9.9.9.9"),
                               "payload": q})())
    qs = ex.drain()
    assert len(qs) == 1 and qs[0]["registrable"] == "x7h2q.com"
    assert qs[0]["max_label"] == 5 and qs[0]["qlen"] == len("aval.x7h2q.com")
    d = DNSDetector(min_queries=1)
    # many unique high-entropy names -> DGA fires
    queries = [{"ts": 1.0 + i, "qname": f"host{i}", "registrable": "x.com",
                "qlen": 20, "n_labels": 3, "max_label": 8,
                "entropy": 4.0, "digit_ratio": 0.4, "qtype": 1,
                "src": "9.9.9.9"} for i in range(10)]
    res = d.score_queries(queries)
    assert any(r.subtype == "DGA_DOMAIN" for r in res)


def test_dns_tunnel_score():
    d = DNSDetector(min_queries=2)
    long_label = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6"  # 52 chars
    queries = [{"ts": 1.0 + i, "qname": long_label + ".t.example.com",
                "registrable": "example.com", "qlen": 75, "n_labels": 4,
                "max_label": 52, "entropy": 4.1, "digit_ratio": 0.5,
                "qtype": 16, "src": "9.9.9.9"} for i in range(6)]
    res = d.score_queries(queries)
    assert any(r.subtype == "DNS_TUNNEL" for r in res)


def test_tls_fingerprint_or_unavailable():
    tls = TLSMetaDetector(min_sessions=2)
    # minimal ClientHello skeleton (record+handshake header only -> fingerprint
    # derivation fails -> must be reported unavailable, never fabricated)
    ch = b"\x16\x03\x01\x00\x05" + b"\x01\x00\x00\x01\x00"
    for i in range(4):
        tls.observe(type("PV", (), {"proto": 6, "ts": float(i),
                                    "src_b": bytes([1, 2, 3, 4]),
                                    "dst_b": bytes([9, 9, 9, 9]),
                                    "dport": 443, "payload": ch})())
    res = tls.drain()
    assert res and res[0].evidence["fingerprint_available"] is False
    assert res[0].evidence["fingerprint"] == "fingerprint_unavailable"


def test_exfil_detector_ratio_gated():
    d = ExfilDetector()
    from src.streaming.detectors import HostWindow
    hw = HostWindow()
    hw.bytes_out, hw.bytes_in, hw.out_flows = 50_000_000, 1_000, 4
    hw.dst_ips = {"a", "b", "c"}
    r = d.score_host("h", hw, 0.0, 10.0)
    assert r is not None and r.active
    hw2 = HostWindow(); hw2.bytes_out, hw2.bytes_in = 100, 90  # tiny transfer
    assert d.score_host("h", hw2, 0.0, 10.0) is None


# ---------------------------------------------------------------------- #
# fusion

def test_fusion_primary_secondary_and_persistence():
    f = ThreatFusion()
    from src.streaming.detectors import DetectorResult
    rs = [DetectorResult("RECON", 0.7, 0.7, {"p": 1}, subtype="PORT_SCAN", active=True),
          DetectorResult("C2", 0.6, 0.6, {"c": 1}, subtype="LIKELY_BEACON", active=True)]
    fused = f.fuse(rs, entity="h1")
    assert fused["threat_class"] == "RECON"
    assert fused["secondary"][0]["threat_class"] == "C2"
    assert fused["evidence"]["_fusion"]["formula"].startswith("max(class_scores)")
    f2 = ThreatFusion(persistence_bonus=0.1)
    f2.fuse(rs, entity="h2")
    again = f2.fuse(rs, entity="h2")
    assert again["evidence"]["_fusion"]["persistence_windows"] == 2
    assert again["risk"] > fused["risk"] or again["risk"] >= rs[0].score


# ---------------------------------------------------------------------- #
# end-to-end service

def test_service_recon_alert_and_contract():
    svc = StreamingService(window_sec=3.0, agg_window_sec=10.0, state="REPLAY")
    frames = []
    t = 1000.0
    for i in range(24):
        frames.append((t, eth_ip_tcp("10.9.9.9", "10.0.0.1", 40000 + i, 20 + i, 0x02)))
        t += 0.05
    feed_frames(svc, frames)
    alerts = svc.drain_alerts()
    assert any(a.threat_class == "RECON" for a in alerts)
    a = [x for x in alerts if x.threat_class == "RECON"][0]
    assert a.state == "REPLAY" and a.evidence
    assert a.model.name.startswith("rule-")


def test_service_c2_alert():
    svc = StreamingService(window_sec=3.0, agg_window_sec=10.0, state="REPLAY")
    frames = []
    t = 2000.0
    for i in range(10):                        # 30 s beacon, small flows
        frames.append((t, eth_ip_tcp("10.5.5.5", "10.6.6.6", 44444, 8443, 0x02)))
        t += 30.0
    feed_frames(svc, frames)
    alerts = svc.drain_alerts()
    c2 = [a for a in alerts if a.threat_class == "C2"]
    assert c2 and c2[0].subtype in ("SUSPICIOUS", "LIKELY_BEACON")
    assert "interval_cv" in c2[0].evidence["C2"]


def test_service_dns_alert():
    svc = StreamingService(window_sec=3.0, agg_window_sec=10.0, state="REPLAY")
    frames = []
    t = 3000.0
    for i in range(8):
        # one registrable parent, many unique high-entropy subdomains
        qname = f"h{i:02d}x7h2q9k4r1t5v8w2y6.badges4all.com".encode()
        parts = qname.split(b".")
        q = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        for part in parts:
            q += bytes([len(part)]) + part
        q += b"\x00\x00\x10\x00\x01"
        frames.append((t, eth_ip_udp("10.7.7.7", "10.0.0.53", 53000 + i, 53, q)))
        t += 0.2
    feed_frames(svc, frames)
    alerts = svc.drain_alerts()
    assert any(a.threat_class == "DGA" for a in alerts)


def test_service_exfil_alert():
    svc = StreamingService(window_sec=3.0, agg_window_sec=10.0, state="REPLAY",
                           exfil_min_bytes_out=10_000)   # fixture-scale threshold
    frames = []
    t = 4000.0
    for i in range(8):
        frames.append((t, eth_ip_tcp("10.8.8.8", f"10.9.{i}.1", 51000 + i, 443, 0x18,
                                     payload=b"\x00" * 1400)))
        t += 0.3
    feed_frames(svc, frames)
    alerts = svc.drain_alerts()
    ex = [a for a in alerts if a.threat_class == "EXFIL"]
    assert ex and ex[0].evidence["EXFIL"]["bytes_out"] > 0
    assert ex[0].evidence["EXFIL"]["outbound_ratio"] >= 8.0


def test_pcap_source_packet_view_parity():
    frames = [(1.0, eth_ip_udp("1.1.1.1", "2.2.2.2", 1111, 53, b"abcd")),
              (1.1, eth_ip_tcp("3.3.3.3", "4.4.4.4", 2222, 80, 0x02))]
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "x.pcap"
        write_pcap(p, frames)
        src = PcapPacketSource(p)
        pkts = list(src)
    assert src.stats["packets"] == 2 and src.stats["parsed"] == 2
    assert pkts[0].proto == 17 and pkts[0].dport == 53
    assert pkts[1].proto == 6 and pkts[1].tcp_flags == 0x02
    assert pkts[1].payload == b"" and pkts[1].payload_len == 0


def test_state_never_grows_unbounded():
    svc = StreamingService(window_sec=1.0, agg_window_sec=5.0, state="REPLAY")
    frames = []
    t = 10_000.0
    for i in range(500):
        frames.append((t, eth_ip_udp(f"10.{i % 250}.{i % 7}.1", "10.0.0.53",
                                     20000 + i, 53, b"\x00" * 32)))
        t += 0.01
    feed_frames(svc, frames)
    assert svc.store.size() < 5_000            # TTL/capacity holds


# ---------------------------------------------------------------------- #
# dashboard bridge + live/replay separation

def test_bridge_document_contract_and_modes():
    a = AlertEvent(
        event_id="x", timestamp="2026-01-01T00:00:00.000+00:00", flow_id="f",
        source_ip="1.2.3.4", destination_ip="5.6.7.8", source_port=1,
        destination_port=2, protocol="TCP", threat_class="DDOS",
        subtype="VOLUMETRIC", prediction="ATTACK", confidence=0.97, risk=0.91,
        stage="DDOS", technique="T1498", observation_window_sec=3.0,
        evidence={"DDOS": {"packets_per_sec": 1200.0}},
        model=ModelIdentity("ddos-frozen-et", "1.0", 0.5), latency_ms=2.0,
        state="LIVE",
    )
    b = DashboardBridge(path="unused.json")
    b.ingest(a)
    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        out = str(Path(td) / "data.json")
        b2 = DashboardBridge(path=out)
        b2.ingest(a)
        b2.write(mode="LIVE", source="netra-streaming", registry_rows=[
            {"name": "ddos-frozen-et", "version": "1.0", "features": 66,
             "calibration": "sigmoid", "threshold": 0.5,
             "evaluation": "capture-disjoint"}],
            metrics_snapshot={"packets_per_sec": 10.0, "flows_scored": 1})
        doc = json.loads(Path(out).read_text(encoding="utf-8"))
        assert doc["meta"]["schema_version"] == 1
        assert doc["meta"]["mode"] == "LIVE"
        assert doc["windows"] and doc["windows"][-1]["alert"] is True
        assert doc["hosts"][0]["ip"] == "1.2.3.4"
        assert "streamingMetrics" in doc["overview"]


def test_no_synthetic_risk_values_reachable():
    """The old scripted emitter (risk = 0.24 + i*0.005) must not be reachable
    from the live path: DashboardBridge only consumes AlertEvents."""
    import inspect
    from src.streaming import emit as emit_mod
    src = inspect.getsource(emit_mod)
    assert "0.24" not in src and "0.005" not in src
    sig = inspect.signature(DashboardBridge.ingest)
    assert "AlertEvent" in str(sig)
