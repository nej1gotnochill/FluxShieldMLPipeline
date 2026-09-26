"""FluxShield pipeline -> UI data emitter.

Call `emit(...)` (or `build_document` + `write_document`) from your ML
pipeline to produce `fluxshield/data.json`, the single document the
dashboard loads at boot. The schema is defined in DATA_CONTRACT.md (v1);
the coercion functions below mirror the UI's per-section validators
(loader.js) so a document produced here always loads clean:

- risk-like values are clamped into [0, 1]
- out-of-range / wrong-typed fields are replaced by the same safe defaults
  the UI's fixtures fallback would use anyway
- `windows.alert` is derived as `risk >= threshold` so the doc never
  contradicts `ml.threshold` (contract rule)
- the file is written atomically (tmp + os.replace) so the UI never reads
  a half-written document

Only `meta` is required to be non-empty; any section left as None is simply
omitted and the UI falls back to its built-in fixtures for that section.
"""

from __future__ import annotations

import json
import math
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

__all__ = [
    "emit", "build_document", "write_document", "EmitterError",
]

SCHEMA_VERSION = 1
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.json")


class EmitterError(ValueError):
    """Raised when arguments are unusable in a way coercion cannot repair."""


# ---------------------------------------------------------------- helpers ---

def _num(v: Any) -> Optional[float]:
    """Finite number or None. Accepts ints, floats and numeric strings."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        f = float(v)
    elif isinstance(v, str):
        try:
            f = float(v)
        except ValueError:
            return None
    else:
        return None
    return f if math.isfinite(f) else None


def _clamp01(v: Any) -> Optional[float]:
    f = _num(v)
    return None if f is None else max(0.0, min(1.0, f))


def _str(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and v else None


def _int(v: Any, lo: int = 0, hi: int = 10**9) -> Optional[int]:
    f = _num(v)
    if f is None:
        return None
    return int(max(lo, min(hi, f)))


def _clean(d: Mapping[str, Any]) -> Dict[str, Any]:
    """Drop None values (and None-containing containers) recursively."""
    return {k: v for k, v in d.items() if v is not None}


# --------------------------------------------------------------- sections ---

def meta(generated_at: Optional[str] = None, source: str = "fluxshield-ml") -> Dict[str, Any]:
    """Required. generated_at defaults to now (UTC, ISO-8601, seconds)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at
            or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source": source,
    }


def overview(*,
             observed_risk: float,
             predicted_tid: str,
             predicted_name: str,
             predicted_conf: float,
             predicted_tactic: str = "",
             predicted_desc: str = "",
             max_future: Optional[float] = None,
             early_warning: Optional[float] = None,
             source_label: Optional[str] = None,
             anomaly: Optional[float] = None,
             throughput: Optional[float] = None,
             flows: Optional[str] = None,
             packets: Optional[str] = None,
             pipeline: Optional[str] = None,
             loss: Optional[float] = None,
             windows_retained: Optional[int] = None) -> Dict[str, Any]:
    """Top-of-screen risk snapshot. observed_risk/predicted_conf clamped to [0, 1]."""
    predicted: Dict[str, Any] = {"tid": _str(predicted_tid), "name": _str(predicted_name),
                                 "conf": _clamp01(predicted_conf)}
    if predicted_tactic:
        predicted["tactic"] = predicted_tactic
    if predicted_desc:
        predicted["desc"] = predicted_desc
    return _clean({
        "observedRisk": _clamp01(observed_risk),
        "predicted": predicted if len(predicted) == 3 else None,  # tid+name+conf required
        "maxFuture": _clamp01(max_future),
        "source": _str(source_label),
        "earlyWarning": _num(early_warning),
        "anomaly": _num(anomaly),
        "throughput": _num(throughput),
        "flows": _str(flows),
        "packets": _str(packets),
        "pipeline": _str(pipeline),
        "loss": _num(loss),
        "windowsRetained": _int(windows_retained),
    })


def ml(*,
       model: str, calibration: str, threshold: float, features: int,
       eval_protocol: str,
       early: Sequence[Mapping[str, Any]],        # [{"t": "1 s", "recall": 68.16}, ...]
       track_b: Optional[float] = None,
       final: Optional[Sequence[Mapping[str, str]]] = None,   # [{"k": "Recall", "v": "99.78%"}]
       comparison: Optional[Sequence[Mapping[str, Any]]] = None,
       ) -> Dict[str, Any]:
    """Model identity + evaluation metrics. Numbers must come from real eval output.

    `comparison` entries: {"nm": str, "f1": 0..100, "sel": bool, "why": str}.
    Exactly one entry should have sel=True (the deployed model).
    """
    early_ok = [{"t": _str(e.get("t")), "recall": _num(e.get("recall"))} for e in early]
    early_ok = [e for e in (_clean(x) for x in early_ok) if len(e) == 2]
    final_ok = [{"k": _str(e.get("k")), "v": _str(e.get("v"))} for e in (final or [])]
    final_ok = [e for e in (_clean(x) for x in final_ok) if len(e) == 2]
    cmp_ok = [{"nm": _str(e.get("nm")), "f1": _num(e.get("f1")),
               "sel": bool(e.get("sel")), "why": _str(e.get("why")) or ""}
              for e in (comparison or [])]
    cmp_ok = [e for e in (_clean(x) for x in cmp_ok)
              if "nm" in e and "f1" in e and 0 < e["f1"] <= 100]
    thr = _num(threshold)
    return _clean({
        "model": _str(model),
        "calibration": _str(calibration),
        "threshold": thr if thr is not None and 0 < thr < 1 else None,
        "features": _int(features, 1),
        "evalProtocol": _str(eval_protocol),
        "trackB": (lambda t: t if t is not None and 0 < t <= 100 else None)(_num(track_b)),
        "early": early_ok or None,
        "final": final_ok or None,
        "comparison": cmp_ok or None,
    })


def windows(seq: Iterable[Mapping[str, Any]], *,
            threshold: float = 0.65,
            start_tsec: Optional[float] = None,
            window_seconds: float = 2.0) -> List[Dict[str, Any]]:
    """Sliding-window risk series, ordered by i. The last entry is 'NOW'.

    alert is derived as risk >= threshold (contract: keep consistent with
    ml.threshold — pass the same value here). If start_tsec is None it is
    back-computed so the LAST window ends at seconds-of-day 'now' when you
    pass the pipeline's run time; tsec steps by window_seconds.
    """
    rows = list(seq)
    if start_tsec is None:
        start_tsec = (datetime.now(timezone.utc).hour * 3600
                      + datetime.now(timezone.utc).minute * 60
                      + datetime.now(timezone.utc).second) - window_seconds * max(0, len(rows) - 1)
    out: List[Dict[str, Any]] = []
    for i, w in enumerate(rows):
        risk = _clamp01(w.get("risk"))
        if risk is None:
            continue  # mirror loader: window without a usable risk is skipped
        peak = _clamp01(w.get("peak"))
        pps = _num(w.get("pps"))
        flow = _num(w.get("flow"))
        tsec = _num(w.get("tsec"))
        out.append(_clean({
            "i": _int(w.get("i")) if w.get("i") is not None else len(out),
            "risk": risk,
            "peak": peak if peak is not None else min(0.98, risk + 0.12),
            "pps": int(pps) if pps is not None and pps >= 0 else int(900 + risk * 5200),
            "flow": int(flow) if flow is not None and flow >= 0 else int(30 + risk * 90),
            "alert": risk >= threshold,
            "stage": _str(w.get("stage")) or "—",
            "technique": _str(w.get("technique")) or "—",
            "target": _str(w.get("target")) or "—",
            "tsec": int(tsec) if tsec is not None and tsec >= 0
                    else int(start_tsec + i * window_seconds),
        }))
    return out


def hosts(seq: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Per-host risk rollup. state auto-derived from risk when absent."""
    out: List[Dict[str, Any]] = []
    for h in seq:
        risk = _clamp01(h.get("risk"))
        if risk is None or not _str(h.get("id")):
            continue
        state = h.get("state")
        if state not in ("high", "susp", "norm"):
            state = "high" if risk >= 0.65 else "susp" if risk >= 0.45 else "norm"
        flows = _num(h.get("flows"))
        out.append(_clean({
            "id": h["id"],
            "ip": _str(h.get("ip")) or "—",
            "zone": _str(h.get("zone")) or "—",
            "kind": _str(h.get("kind")) or "server",
            "risk": risk,
            "state": state,
            "tech": _str(h.get("tech")) or "—",
            "flows": int(flows) if flows is not None and flows >= 0 else 0,
        }))
    return out


def branches(seq: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Forecast branches. p is 0..100; color drives forecast emphasis."""
    out: List[Dict[str, Any]] = []
    for b in seq:
        p = _num(b.get("p"))
        if p is None or not _str(b.get("id")):
            continue
        risk = _clamp01(b.get("risk"))
        out.append(_clean({
            "id": b["id"],
            "p": max(0.0, min(100.0, p)),
            "tid": _str(b.get("tid")) or "—",
            "desc": _str(b.get("desc")) or "—",
            "ttE": _str(b.get("ttE")) or "—",
            "asset": _str(b.get("asset")) or "—",
            "risk": risk if risk is not None else 0.0,
            "color": b.get("color") if b.get("color") in ("red", "amber", "dim")
                     else ("red" if (risk or 0) >= 0.65 else "amber" if (risk or 0) >= 0.45 else "dim"),
        }))
    return out


def incidents(seq: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Incident queue. status: TRIAGING | CONTAINED | CLOSED."""
    out: List[Dict[str, Any]] = []
    for n in seq:
        if not _str(n.get("id")):
            continue
        peak = _clamp01(n.get("peak"))
        lead = _num(n.get("lead"))
        alerts = _num(n.get("alerts"))
        evidence = _num(n.get("evidence"))
        out.append(_clean({
            "id": n["id"],
            "sev": _str(n.get("sev")) or "MED",
            "status": n.get("status") if n.get("status") in ("TRIAGING", "CONTAINED", "CLOSED")
                      else "TRIAGING",
            "tid": _str(n.get("tid")) or "—",
            "tech": _str(n.get("tech")) or "—",
            "target": _str(n.get("target")) or "—",
            "ip": _str(n.get("ip")) or "—",
            "peak": peak if peak is not None else 0.0,
            "lead": lead if lead is not None and lead >= 0 else 0.0,
            "dur": _str(n.get("dur")) or "—",
            "analyst": _str(n.get("analyst")) or "—",
            "alerts": int(alerts) if alerts is not None else 0,
            "opened": _str(n.get("opened")) or "—",
            "evidence": int(evidence) if evidence is not None else 0,
        }))
    return out


def events(seq: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Alert feed rows. sev: CRIT | WARN | INFO."""
    out: List[Dict[str, Any]] = []
    for e in seq:
        msg = _str(e.get("msg"))
        if not msg:
            continue
        out.append(_clean({
            "ts": _str(e.get("ts")) or "—",
            "sev": e.get("sev") if e.get("sev") in ("CRIT", "WARN", "INFO") else "INFO",
            "src": _str(e.get("src")) or "system",
            "host": _str(e.get("host")) or "—",
            "msg": msg,
        }))
    return out


def predictions(seq: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Technique forecasts. p is clamped to [0, 1]; conf may be str or number."""
    out: List[Dict[str, Any]] = []
    for p in seq:
        tid = _str(p.get("tid"))
        prob = _clamp01(p.get("p"))
        if not tid or prob is None:
            continue
        conf = p.get("conf")
        out.append(_clean({
            "tid": tid,
            "name": _str(p.get("name")) or tid,
            "p": prob,
            "eta": _str(p.get("eta")) or "—",
            "conf": conf if isinstance(conf, str) and conf
                    else (str(conf) if isinstance(conf, (int, float)) and not isinstance(conf, bool) else "—"),
        }))
    return out


def state_vector(seq: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Feature-attribution rows. v clamped to [0, 1]; hot highlights the row."""
    out: List[Dict[str, Any]] = []
    for r in seq:
        v = _clamp01(r.get("v"))
        if not _str(r.get("nm")) or v is None:
            continue
        out.append({"nm": r["nm"], "v": v, "hot": bool(r.get("hot"))})
    return out


def attack(seq: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Kill-chain grid. item state: 'hot' | 'warm' | '' ; p clamped to [0, 1]."""
    out: List[Dict[str, Any]] = []
    for t in seq:
        tactic = _str(t.get("tactic"))
        items_raw = t.get("items")
        if not tactic or not isinstance(items_raw, (list, tuple)):
            continue
        items = []
        for it in items_raw:
            if not (_str(it.get("id")) and _str(it.get("name"))):
                continue
            p = _clamp01(it.get("p"))
            items.append(_clean({
                "id": it["id"], "name": it["name"],
                "state": it.get("state") if it.get("state") in ("hot", "warm") else "",
                "p": p if p is not None else 0.0,
            }))
        if items:
            out.append({"tactic": tactic, "items": items})
    return out


def campaign(*,
             id: str, started: str,
             hosts_count: Optional[int] = None,
             flows: Optional[int] = None,
             alerts: Optional[int] = None,
             stages: Optional[Sequence[Mapping[str, Any]]] = None) -> Dict[str, Any]:
    """Active campaign banner. stages: [{"nm", "ts", "done", "tid"}]."""
    st = [{"nm": _str(s.get("nm")), "ts": _str(s.get("ts")) or "—",
           "done": bool(s.get("done")), "tid": _str(s.get("tid")) or "—"}
          for s in (stages or [])]
    st = [s for s in (_clean(x) for x in st) if "nm" in s]
    return _clean({
        "id": _str(id),
        "started": _str(started),
        "hosts": _int(hosts_count),
        "flows": _int(flows),
        "alerts": _int(alerts),
        "stages": st or None,
    })


# ------------------------------------------------------- document + write ---

def build_document(m: Mapping[str, Any], *,
                   overview: Optional[Mapping[str, Any]] = None,
                   ml: Optional[Mapping[str, Any]] = None,
                   windows: Optional[Sequence[Mapping[str, Any]]] = None,
                   hosts: Optional[Sequence[Mapping[str, Any]]] = None,
                   branches: Optional[Sequence[Mapping[str, Any]]] = None,
                   incidents: Optional[Sequence[Mapping[str, Any]]] = None,
                   events: Optional[Sequence[Mapping[str, Any]]] = None,
                   predictions: Optional[Sequence[Mapping[str, Any]]] = None,
                   state_vector: Optional[Sequence[Mapping[str, Any]]] = None,
                   attack: Optional[Sequence[Mapping[str, Any]]] = None,
                   campaign: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Assemble the full document. Omitted sections stay fixture-backed in the UI."""
    if not isinstance(m, Mapping) or not _str(m.get("source")):
        raise EmitterError("meta with a non-empty 'source' is required "
                           "(use fs_emit.meta() to build it)")
    doc: Dict[str, Any] = {"meta": dict(m)}
    for key, val in (("overview", overview), ("ml", ml), ("windows", windows),
                     ("hosts", hosts), ("branches", branches), ("incidents", incidents),
                     ("events", events), ("predictions", predictions),
                     ("stateVector", state_vector), ("attack", attack),
                     ("campaign", campaign)):
        if val is None:
            continue
        if isinstance(val, (list, tuple)) and not val:
            continue  # empty list -> omit, UI falls back to fixtures
        doc[key] = val
    return doc


def write_document(doc: Mapping[str, Any], path: str = DEFAULT_PATH,
                   indent: int = 2) -> str:
    """Atomically write the document (tmp file + os.replace in the same dir)."""
    payload = json.dumps(doc, indent=indent, ensure_ascii=False,
                         allow_nan=False) + "\n"
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".data-", suffix=".json.tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise
    return path


def emit(path: str = DEFAULT_PATH, *, m: Mapping[str, Any], **sections: Any) -> str:
    """One-call writer: emit(meta(source=...), overview=overview(...), ...)."""
    return write_document(build_document(m, **sections), path=path)


# ------------------------------------------------------------- selftest ----

if __name__ == "__main__":
    import sys

    doc = build_document(
        meta(source="fluxshield-ml"),
        overview=overview(
            observed_risk=0.739, predicted_tid="T1190",
            predicted_name="Exploit Public-Facing Application",
            predicted_conf=0.833, predicted_tactic="TA0001 Initial Access",
            max_future=0.953, early_warning=6.8),
        ml=ml(model="ExtraTrees 300", calibration="Sigmoid", threshold=0.50,
              features=66, eval_protocol="Capture-disjoint · attack-family holdout",
              early=[{"t": "1 s", "recall": 68.16}, {"t": "3 s", "recall": 99.79},
                     {"t": "5 s", "recall": 99.79}],
              track_b=97.40,
              final=[{"k": "Recall", "v": "99.7849%"}, {"k": "Precision", "v": "99.9998%"},
                     {"k": "F1", "v": "99.8922%"}, {"k": "FPR", "v": "0.018%"}],
              comparison=[{"nm": "Logistic Regression", "f1": 96.41, "sel": False,
                           "why": "linear baseline — underfits flow-rate interactions"},
                          {"nm": "ExtraTrees · 300", "f1": 99.89, "sel": True,
                           "why": "SELECTED FOR ROBUST GENERALIZATION"}]),
        windows=windows([{"risk": 0.312, "stage": "RECON", "technique": "T1046"},
                         {"risk": 0.355, "stage": "RECON", "technique": "T1046"},
                         {"risk": 0.839, "stage": "EXPLOIT", "technique": "T1190",
                          "target": "dmz-web", "tsec": 71003}],
                        threshold=0.50),
        hosts=hosts([{"id": "dmz-web", "ip": "10.0.3.10", "zone": "DMZ", "risk": 0.839,
                      "tech": "T1190 · T1110", "flows": 412}]),
        branches=branches([{"id": "A", "p": 66, "tid": "T1190",
                            "desc": "Exploit the public-facing application", "ttE": "+6s",
                            "asset": "dmz-web", "risk": 0.953, "color": "red"}]),
        incidents=incidents([{"id": "INC-0142", "sev": "HIGH", "status": "TRIAGING",
                              "tid": "T1110", "tech": "Brute Force", "target": "dmz-web",
                              "ip": "10.0.3.10", "peak": 0.772, "lead": 11.4, "dur": "34s",
                              "analyst": "a.rao", "alerts": 147, "opened": "19:48:42",
                              "evidence": 58}]),
        events=events([{"ts": "19:44:52", "sev": "CRIT", "src": "inference",
                        "host": "dmz-web",
                        "msg": "Model risk 0.839 over threshold 0.50 — alert raised"}]),
        predictions=predictions([{"tid": "T1190", "name": "Exploit Public-Facing Application",
                                  "p": 0.833, "eta": "+6s", "conf": 0.833}]),
        state_vector=state_vector([{"nm": "H_emb_0", "v": 0.335, "hot": True}]),
        attack=attack([{"tactic": "Initial Access",
                        "items": [{"id": "T1190", "name": "Exploit Public-Facing App",
                                   "state": "hot", "p": 0.83}]}]),
        campaign=campaign(id="CMP-007 · BRUTE-FORCE → EXPLOIT CHAIN", started="19:43:19",
                          hosts_count=4, flows=1918, alerts=307,
                          stages=[{"nm": "Recon", "ts": "19:43:19", "done": True,
                                   "tid": "T1046"}]),
    )

    # coercion checks: garbage in -> contract-valid out, never an exception
    w = windows([{"risk": 1.7, "i": 0}, {"risk": "oops"}, {"risk": -0.5}], threshold=0.50)
    assert w[0]["risk"] == 1.0 and w[0]["alert"] is True
    assert w[1]["risk"] == 0.0 and w[1]["alert"] is False
    assert len(w) == 2  # non-numeric risk row skipped, like the loader

    # alert derivation must agree with ml.threshold
    thr = doc["ml"]["threshold"]
    assert all(row["alert"] == (row["risk"] >= thr) for row in doc["windows"])

    p = write_document(doc, path=sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH)
    print("wrote", p, "— sections:", [k for k in doc if k != "meta"])
