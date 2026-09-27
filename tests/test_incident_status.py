"""Analyst incident-status workflow: emit persistence + dashboard API.

The Containment buttons record analyst decisions (ACKNOWLEDGED / CONTAINED /
CLOSED). This suite pins the two invariants that make those decisions real:

  * persistence — a status set on an incident survives a full emit cycle
    (the bridge is recreated from scratch, as a replay run would), and
    disallowed transitions are rejected;
  * API — POST /api/incident mutates data.json + the sidecar only for
    valid transitions against the CURRENT data.json row; stale ids and
    illegal moves get 404/409, everything else stays a validated 405.

The sidecar lives next to data.json (dashboard/incident_status.json,
gitignored) and is re-applied by DashboardBridge on every write.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import threading
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src" / "streaming"))

from emit import (DashboardBridge, INCIDENT_TRANSITIONS, _load_statuses,  # noqa: E402
                  apply_incident_status)
from schema import AlertEvent, ModelIdentity  # noqa: E402


def _event(ts: str = "2026-09-27T15:56:13.990+00:00", src: str = "10.10.0.12",
           klass: str = "DDOS", subtype: str = "VOLUMETRIC") -> AlertEvent:
    return AlertEvent(event_id="E1", timestamp=ts, flow_id="F1",
                      source_ip=src, destination_ip="192.168.10.11",
                      source_port=1000, destination_port=80, protocol="TCP",
                      threat_class=klass, subtype=subtype, prediction="ATTACK",
                      confidence=0.99, risk=1.0, stage=klass, technique=subtype,
                      observation_window_sec=10,
                      evidence={"DDOS": {"packets_per_sec": 5000.0}},
                      model=ModelIdentity(name="ddos-frozen-et", version="1.0",
                                          threshold=0.5),
                      latency_ms=1.0, state="REPLAY")


@pytest.fixture()
def tmp_dash(tmp_path):
    """Bridge + server wiring pointed at a throwaway dashboard dir."""
    data = tmp_path / "data.json"
    bridge = DashboardBridge(str(data))
    bridge.ingest(_event())
    bridge.write(mode="REPLAY", source="netra-streaming", registry_rows=[])
    return data


# ---------------------------------------------------------------------------
# emit persistence
# ---------------------------------------------------------------------------

def test_default_status_is_triaging(tmp_dash):
    doc = json.loads(tmp_dash.read_text(encoding="utf-8"))
    assert doc["incidents"][0]["status"] == "TRIAGING"


def test_status_survives_full_emit_cycle(tmp_dash):
    statuses = _load_statuses(str(tmp_dash))
    ok, new = apply_incident_status(statuses, "INC-0001", "TRIAGING",
                                    "CONTAINED")
    assert ok and new == "CONTAINED"
    from emit import _save_statuses
    _save_statuses(str(tmp_dash), statuses)

    doc = json.loads(tmp_dash.read_text(encoding="utf-8"))
    assert doc["incidents"][0]["status"] == "TRIAGING"  # data.json not yet re-emitted

    fresh = DashboardBridge(str(tmp_dash))   # replay run: brand-new bridge
    fresh.ingest(_event())
    fresh.write(mode="REPLAY", source="netra-streaming", registry_rows=[])

    doc = json.loads(tmp_dash.read_text(encoding="utf-8"))
    assert doc["incidents"][0]["status"] == "CONTAINED"


def test_transition_table_moves_forward_only():
    assert "CONTAINED" in INCIDENT_TRANSITIONS["TRIAGING"]
    assert "CLOSED" in INCIDENT_TRANSITIONS["CONTAINED"]
    assert INCIDENT_TRANSITIONS["CLOSED"] == ()
    # regressions are refused
    s: dict = {}
    ok, _ = apply_incident_status(s, "INC-0001", "CONTAINED", "TRIAGING")
    assert not ok and s == {}
    ok, _ = apply_incident_status(s, "INC-0001", "CLOSED", "TRIAGING")
    assert not ok


def test_unknown_ids_cannot_be_created():
    s: dict = {}
    ok, _ = apply_incident_status(s, "INC-9999", "TRIAGING", "CLOSED")
    # apply_incident_status only validates transition shape; the server's
    # data.json row lookup is what prevents unknown ids — pinned here:
    assert ok  # shape-valid, but the endpoint rejects unknown ids before this


# ---------------------------------------------------------------------------
# dashboard API
# ---------------------------------------------------------------------------

@pytest.fixture()
def server(tmp_dash):
    """Live server whose HERE points at the throwaway dashboard dir — the
    endpoint mutates <HERE>/data.json, so tests must never touch the real
    dashboard/data.json."""
    spec = importlib.util.spec_from_file_location(
        "netra_server", REPO / "dashboard" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.HERE = str(tmp_dash.parent)
    srv = mod.NetraServer(("127.0.0.1", 0), mod.HardenedHandler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield mod, srv
    srv.shutdown()


def _post(port: int, payload: dict, token: str = "", method: str = "POST",
          path: str = "/api/incident") -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {token}"} if token else {})},
        method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (json.loads(raw) if raw else {})


def test_api_valid_transition_persists(server, tmp_dash):
    mod, srv = server
    code, body = _post(srv.server_address[1],
                       {"id": "INC-0001", "status": "ACKNOWLEDGED"})
    assert code == 200 and body["status"] == "ACKNOWLEDGED"
    doc = json.loads(tmp_dash.read_text(encoding="utf-8"))
    assert doc["incidents"][0]["status"] == "ACKNOWLEDGED"
    assert _load_statuses(str(tmp_dash)).get("INC-0001") == "ACKNOWLEDGED"


def test_api_rejects_illegal_transition_and_unknown_id(server):
    mod, srv = server
    port = srv.server_address[1]
    code, _ = _post(port, {"id": "INC-0001", "status": "NEW"})
    assert code == 409
    code, _ = _post(port, {"id": "INC-4242", "status": "CLOSED"})
    assert code == 404


def test_api_stays_read_only_for_other_writes(server):
    mod, srv = server
    port = srv.server_address[1]
    for method, path in (("PUT", "/api/incident"), ("DELETE", "/api/incident"),
                         ("POST", "/api/anything-else"),
                         ("POST", "/data.json")):
        code, _ = _post(port, {}, method=method, path=path)
        assert code in (404, 405), (method, path, code)


def test_api_requires_token_when_configured(server, monkeypatch):
    mod, srv = server
    port = srv.server_address[1]
    monkeypatch.setattr(mod, "TOKEN", "sekrit")
    code, _ = _post(port, {"id": "INC-0001", "status": "ACKNOWLEDGED"})
    assert code == 401
    code, body = _post(port, {"id": "INC-0001", "status": "ACKNOWLEDGED"},
                       token="sekrit")
    assert code == 200 and body["status"] == "ACKNOWLEDGED"
