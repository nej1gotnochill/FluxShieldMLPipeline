# FluxShield UI data contract — v1

The dashboard reads a single JSON document. Your ML pipeline writes it; the UI renders it.
No other backend changes are required on the UI side.

## File

`fluxshield/data.json` — written by your pipeline (any language), fetched by the UI at boot.

## Loading behavior

- The app fetches `data.json` at startup (relative to the page URL), then **re-fetches
  every 30 seconds**. Polls while the tab is hidden are skipped; on tab re-visibility
  the app catches up immediately.
- **Change detection:** if the re-fetched document produces the same merged state as
  the current one (e.g. only `generated_at` moved), nothing re-renders. When content
  changes, the badge/tooltip refresh and the active screen re-renders in place (no
  full page reload; selection state like replay position and open incident survives).
- **Poll failure:** a failed poll (server blip) keeps the last good data and provenance
  — the badge stays LIVE until the next successful poll.
- **Validation:** every section is validated; bad/missing values fall back to
  built-in fixtures per-section (the app never breaks because one field is malformed).
- **Per-field coercion:** wrong-typed or out-of-range fields are dropped (or
  clamped, for risks) individually — a single bad field never invalidates its
  whole section, and a section whose entries all fail still falls back to
  fixtures wholesale. Verified against fully corrupted documents (bad risks,
  wrong types, unknown enums, `schema_version` mismatch, sections missing
  mid-session): the UI keeps rendering, re-renders all 12 screens without
  errors, and restores fixtures for any section that disappears or turns invalid.
- **Provenance:** the top bar shows `LIVE DATA` when the document loaded and passed
  validation, or `SIMULATED` when fixtures are used. The tooltip shows the pipeline
  `source` and `generated_at` timestamp. If your pipeline only bumps `generated_at`,
  the UI does not treat it as a data change.
- `meta.schema_version` must be `1`. Future breaking changes bump this and the UI
  ignores unknown versions per-section.
- The loader also exposes `FSLOAD.refresh()`, `FSLOAD.startPolling()` /
  `FSLOAD.stopPolling()`, and fires a `fs:data` DOM event (on `document`) whenever
  live data actually changed.

## Top-level shape

```
{
  "meta":         { schema_version, generated_at, source },
  "overview":     { observedRisk, predicted{tid,name,tactic,conf,desc}, maxFuture,
                    source, earlyWarning, anomaly, throughput, flows, packets,
                    pipeline, loss, windowsRetained },
  "ml":           { model, calibration, threshold, features, evalProtocol,
                    early[{t,recall}], trackB, final[{k,v}], comparison[{nm,f1,sel,why}] },
  "windows":      [ { i, risk, peak, pps, flow, alert, stage, technique, target, tsec } ],
  "hosts":        [ { id, ip, zone, kind, risk, state, tech, flows } ],
  "branches":     [ { id, p, tid, desc, ttE, asset, risk, color } ],
  "incidents":    [ { id, sev, status, tid, tech, target, ip, peak, lead, dur,
                      analyst, alerts, opened, evidence } ],
  "events":       [ { ts, sev, src, host, msg } ],
  "predictions":  [ { tid, name, p, eta, conf } ],
  "stateVector":  [ { nm, v, hot } ],
  "attack":       [ { tactic, items[{id,name,state,p}] } ],
  "campaign":     { id, started, hosts, flows, alerts, stages[{nm,ts,done,tid}] }
}
```

## Field rules

- All risk values are in `[0, 1]`.
- `windows` is ordered by `i`; the UI treats the last entry as NOW and derives the
  replay clock from `tsec` (seconds of day) with 2.0 s window spacing.
- `windows.alert` is `risk >= threshold` — keep consistent with `ml.threshold`.
- `state` per host: `high | susp | norm` (drives node color; risk drives the number).
- `color` per branch: `red | amber | dim` (drives forecast emphasis).
- `sev` per event: `CRIT | WARN | INFO`.
- Incident `status`: `TRIAGING | CONTAINED | CLOSED`.
- ML numbers must come from real evaluation output — the UI never derives or fakes them.

## Minimal viable document

Only `meta` is required. Anything absent falls back to fixtures, so you can ship
sections incrementally as your pipeline produces them:

```
{ "meta": { "schema_version": 1, "generated_at": "2026-09-26T19:45:03Z", "source": "my-pipeline" } }
```

## Writer: `fs_emit.py` (recommended)

`fluxshield/fs_emit.py` implements this contract and mirrors the UI's validation
rules, so anything it emits loads clean. It clamps risks into [0, 1], derives
`windows.alert` from `ml.threshold`, and writes atomically (tmp + rename) so the
UI never reads a half-written file. Omit any section to keep it fixture-backed.

```python
import fs_emit as fs

doc_sections = dict(
    overview=fs.overview(observed_risk=0.739, predicted_tid="T1190",
                         predicted_name="Exploit Public-Facing Application",
                         predicted_conf=0.833, max_future=0.953,
                         early_warning=6.8),
    ml=fs.ml(model="ExtraTrees 300", calibration="Sigmoid", threshold=0.50,
             features=66, eval_protocol="Capture-disjoint · attack-family holdout",
             early=[{"t": "1 s", "recall": 68.16}, {"t": "3 s", "recall": 99.79}],
             track_b=97.40),
    windows=fs.windows(window_rows, threshold=0.50),
    hosts=fs.hosts(host_rows),
)

fs.emit(m=fs.meta(source="fluxshield-ml"), path="data.json", **doc_sections)
```

Run `python fs_emit.py` for a self-test that writes a full sample document.

A hand-rolled writer is fine too — the only hard requirements are `meta` with
`schema_version: 1` and that every field above matches its documented type and
range (the UI falls back per-section on anything it cannot validate):

```python
import json, datetime

doc = {
    "meta": {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "source": "fluxshield-ml",
    },
    # ... sections per the shape above
}
json.dump(doc, open("data.json", "w"))
```
