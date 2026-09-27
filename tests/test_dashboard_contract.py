"""Dashboard data-contract tests (static — no JS runtime required).

The dashboard has one hard rule: **measured pipeline data renders, missing
data renders an explicit placeholder — never invented numbers.** These tests
lock that rule in by statically analyzing the dashboard sources:

  1. index.html is in sync with build.py sources (style/data/loader/charts/app)
  2. app.js contains no fabricated metric literals (the 96.41/99.12/... class
     of hard-coded "measurements" that once shipped on the Model screen)
  3. every D.* section app.js renders is covered by the loader merge map with
     a real validator function
  4. every object field app.js reads off a validated section is an output key
     of the corresponding loader validator (rendered == validated)
  5. missing-data placeholders exist for every panel that once had a
     hard-coded fallback
  6. dashboard/data.json ml.* sections match src/streaming/ml_data.py's parse
     of the committed reports (regenerate emit after reports change)

See dashboard/DATA_CONTRACT.md for the wire contract these tests enforce.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DASH = REPO / "dashboard"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def read(name: str) -> str:
    return (DASH / name).read_text(encoding="utf-8")


def js_code_only(src: str) -> str:
    """Strip comments and string literals so literal scans see code only."""
    src = re.sub(r"/\*[\s\S]*?\*/", " ", src)
    src = re.sub(r"(?<![:\w])//[^\n]*", " ", src)  # keep '://' inside strings
    src = re.sub(r"'(?:[^'\\\n]|\\.)*'", "''", src)
    src = re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', src)
    return src


def fn_block(src: str, name: str) -> str:
    """Return the full source of `function name(...) { ... }` (brace-matched)."""
    m = re.search(r"function " + re.escape(name) + r"\s*\(", src)
    assert m, f"loader.js: missing function {name}"
    i = src.index("{", m.end() - 1)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    raise AssertionError(f"loader.js: unbalanced braces in {name}")


VALIDATOR_KEYS_CACHE: dict[str, set[str]] = {}


def validator_keys(fn_name: str) -> set[str]:
    """Output-object keys emitted by a loader validator.

    Covers both multi-line object literals (key at line start, `name:` without
    a space before the colon) and inline `push({ key: …, key2: … })` blocks.
    The no-space-before-colon rule keeps ternary fallbacks (`v : x`) out.
    """
    if fn_name not in VALIDATOR_KEYS_CACHE:
        block = fn_block(read("loader.js"), fn_name)
        keys = set(re.findall(r"^ {2,}([a-z_][A-Za-z0-9_]*)\s*:", block, re.M))
        for inline in re.findall(r"\(\s*\{([^{}]*)\}", block):
            keys |= set(re.findall(r"([a-z_][A-Za-z0-9_]*):", inline))
        # ['k1','k2',…].forEach(…) whitelists — the streaming metrics keys are
        # validated by membership in such an array, not an object literal
        for arr in re.findall(r"\[([^\[\]]*)\]\.forEach", block):
            keys |= set(re.findall(r"'([a-z_][A-Za-z0-9_]*)'", arr))
        VALIDATOR_KEYS_CACHE[fn_name] = keys
    return VALIDATOR_KEYS_CACHE[fn_name]


# nested passthroughs that validator_keys cannot see (e.g. mm.latency)
EXTRA_ALLOWED = {
    ("vStreaming", "m"): {"latency"},
}


# ---------------------------------------------------------------------------
# 1. build.py sync
# ---------------------------------------------------------------------------

SOURCES = ["style.css", "data.js", "loader.js", "charts.js", "app.js"]


def test_index_html_is_in_sync_with_sources():
    index = read("index.html")
    parts = re.split(r"(<style>|</style>|<script>|</script>)", index)
    markers = parts[1::2]
    texts = parts[0::2]
    assert markers == ["<style>", "</style>"] + ["<script>", "</script>"] * 4, \
        "index.html layout changed — update this test together with build.py"
    for i, name in enumerate(SOURCES):
        chunk = read(name).rstrip("\n")
        assert texts[2 * i + 1].strip("\n") == chunk, (
            f"index.html is stale: {name} changed since the last "
            f"`python build.py` (run it in dashboard/ and commit index.html)"
        )


# ---------------------------------------------------------------------------
# 2. no fabricated metric literals
# ---------------------------------------------------------------------------

# Values that once shipped as hard-coded "measurements" on the Model screen
# (comparison F1s, Track B recall, confusion matrix, inference-log rows).
FORBIDDEN_METRIC_LITERALS = {
    "96.41", "99.12", "99.89", "99.57", "97.40",       # fake model comparison
    "283743", "13842",                                  # fake confusion matrix
    "0.211", "0.094", "0.348",                          # fake inference risks
    "68.16", "99.79",                                   # early-recall ticker copy
}

# Legitimate ≥3-decimal decimals in app.js — chart/animation geometry, not data:
#   12.9898 / 78.233 : isometric map projection seed
#   0.999            : legacy bar-shadow alpha (Model screen)
#   0.006            : exec-trend particle jitter
#   0.012 / 0.015    : forecast band widening per step
#   0.009 / 0.014    : mini replay-bar scrub speeds
#   0.945 / 0.845 ...: network-map zone rail / node layout positions
ALLOWED_LONG_DECIMALS = {
    "12.9898", "78.233", "0.999", "0.006", "0.012", "0.015",
    "0.009", "0.014", "0.945", "0.845", "0.955", "0.8455",
}


def test_app_has_no_fabricated_metric_literals():
    findings = []
    code = js_code_only(read("app.js"))
    literals = set(re.findall(r"(?<![\w.])\d{1,3}\.\d{2,}(?![\w.])", code))
    bad = literals & FORBIDDEN_METRIC_LITERALS
    if bad:
        findings.append(f"app.js: hard-coded metric(s) {sorted(bad)}")
    longs = {
        x for x in literals - ALLOWED_LONG_DECIMALS
        if len(x.split(".")[1]) >= 3
    }
    if longs:
        findings.append(
            f"app.js: data-like decimal(s) {sorted(longs)} — render measured "
            f"values from D.* instead, or extend ALLOWED_LONG_DECIMALS "
            f"with a justification if this really is chart geometry"
        )
    assert not findings, (
        "app.js hard-codes data values that must come from data.json:\n  "
        + "\n  ".join(findings)
    )


# ---------------------------------------------------------------------------
# 3. + 5. merge-map coverage and missing-data placeholders
# ---------------------------------------------------------------------------

def test_every_rendered_section_is_in_the_loader_merge_map():
    app = read("app.js")
    loader = read("loader.js")
    datajs = read("data.js")
    fix_m = re.search(r"var\s+FIXTURES\s*=\s*JSON\.parse\(JSON\.stringify\(\{([\s\S]*?)\}\)\)", datajs)
    assert fix_m, "data.js: FIXTURES snapshot not found (merge() seeds from it)"
    fixture_keys = set(re.findall(r"\b([A-Z][A-Z_]+)\s*:", fix_m.group(1)))
    read_sections = set(re.findall(r"\bD\.([A-Z][A-Z_]+)\b", app))
    merge_map = re.findall(
        r"\['([A-Z][A-Z_]+)',\s*'([a-zA-Z]+)',\s*(v[A-Za-z]+)\]", loader
    )
    mapped = {m[0] for m in merge_map}
    missing = read_sections - mapped
    assert not missing, (
        f"app.js renders D.{sorted(missing)[0]} but the loader merge map has no "
        f"entry for it — unvalidated sections silently bypass the contract; add "
        f"[key, contractKey, validator] to merge() in loader.js"
    )
    for fskey, lkey, fn in merge_map:
        assert re.search(r"function " + fn + r"\s*\(", loader), \
            f"merge map entry ['{fskey}', '{lkey}', {fn}] has no validator function"
        if fskey in fixture_keys:
            assert re.search(r"\b" + re.escape(fskey) + r"\b", datajs), \
                f"FIXTURES lists '{fskey}' but data.js never defines it"
    # live-only sections (no fixture on purpose) must be read defensively in app.js
    for k in mapped - fixture_keys:
        assert re.search(r"D\." + k + r"\s*\|\|", app), (
            f"D.{k} has no built-in fixture, so app.js must read it defensively "
            f"(D.{k} || …) — a missing section would throw at render time"
        )


# (validator, receiver in app.js, fields to ignore (DOM helpers/other loops),
#  explicit field list — None means extract `receiver.field` from app.js)
FIELD_TARGETS = [
    ("vIncidents",  "inc",  set(), None),
    ("vAlerts",     "a",    {"t", "x", "y"}, None),          # exec-trend points
    ("vWindows",    "wv",   set(), None),
    ("vWindows",    "w",    {"appendChild"}, None),
    ("vHosts",      "hh",   set(), None),
    ("vHosts",      "h",    {"cls", "x", "y"}, None),        # network-map nodes
    ("vEvents",     "e2",   set(), None),
    ("vPredictions", "pred", {"appendChild"}, ["tid", "name", "p", "conf", "tactic"]),
    # receiver `s` spans campaign stages (vCampaign), the state vector
    # (vStateVector) and a LOCAL lifecycle-rail stages array whose `t` is
    # defined inline in app.js — the latter cannot be contract-checked
    (None,         "s",    {"mode", "x", "t", "innerHTML", "appendChild", "classList"}, None),
    ("vAttack",     "it",   {"innerHTML", "onclick"}, None),
    ("vStreaming",  "m",    set(), None),   # ST.metrics rows (nested mm whitelist)
    ("vBranches",   "b",    {"appendChild", "classList", "className", "innerHTML",
                             "onclick", "style", "title", "textContent", "x", "y",
                             "t"}, None),   # b.t = sort-comparator callback, not a branch read
    # fixtureEval rows (r.*) live inside vML; detector rows (d.*) span vML+vStreaming
    ("vML",         "r",    {"appendChild", "height", "width", "hot", "k", "nm", "v"},
     ["alerts_by_class", "expected", "total_alerts"]),
    (None,          "d",    {"provenance", "style", "innerHTML"},
     ["name", "version", "kind", "threshold", "status", "last_error", "evaluation"]),
]


def test_every_rendered_field_is_produced_by_its_validator():
    app = read("app.js")
    for fn, recv, ignore, explicit in FIELD_TARGETS:
        fields = set(explicit) if explicit is not None else (
            set(re.findall(r"(?<![\w.])" + recv + r"\.([a-z_]\w*)", app)) - ignore
        )
        assert fields, f"no {recv}.* field reads found — receiver renamed in app.js?"
        allowed: set[str] = set()
        if fn is None:  # detector rows / multi-validator receivers: either source validates
            for alt in (("vML", "vStreaming") if recv == "d" else ("vCampaign", "vStateVector")):
                allowed |= validator_keys(alt)
        else:
            allowed = validator_keys(fn)
        allowed |= EXTRA_ALLOWED.get((fn, recv), set())
        unknown = fields - allowed
        assert not unknown, (
            f"app.js reads {recv}.{sorted(unknown)[0]} but {fn or 'vML/vStreaming'} "
            f"never emits that field — either the loader validator is missing it "
            f"(renders as undefined) or app.js reads an unvalidated object"
        )


PLACEHOLDERS = [
    # (anchor that must exist in app.js, what it guards)
    ("D.ML.comparison || []",                          "Model comparison falls back to []"),
    ("no comparison data in this document",            "Model comparison empty-state"),
    ("M.confusion && typeof M.confusion.tn === 'number') ? M.confusion : null",
                                                       "Confusion matrix null fallback"),
    ("No AlertEvents in this document",                "Inference log empty-state"),
    ("run a replay to populate the registry",          "Detector registry empty-state"),
    ("Partial-evidence recall unavailable",            "Early-detection empty-state"),
    ("unassigned",                                     "Incident analyst fallback"),
    ("M.registry || []",                               "Detector registry data fallback"),
    ("D.ML && D.ML.early) || []",                      "Overview early-recall ticker fallback"),
]


def test_missing_data_renders_placeholders_not_inventions():
    app = read("app.js")
    for anchor, what in PLACEHOLDERS:
        assert anchor in app, (
            f"{what} was removed — panels must render an explicit placeholder "
            f"when data.json lacks the section, never a hard-coded value"
        )


def test_loader_validates_nested_and_new_contract_fields():
    loader = read("loader.js")
    # alert.model is rendered (a.model.name) so it must be structurally validated
    assert "isObj(a.model) && isStr(a.model.name)" in loader, \
        "vAlerts must validate the nested model object (app renders a.model.name)"
    # confusion / registry / modelCount / fixtureEval passthroughs
    for needle in ("isObj(d.confusion)", "m.registry", "m.modelCount", "m.fixtureEval"):
        assert needle in loader, f"vML is missing the {needle} passthrough"
    # validator coerces unknown detector status rather than trusting the wire
    assert "e.status === 'degraded' ? 'degraded' : 'ok'" in loader, \
        "registry/streaming validators must normalize unknown status values"


# ---------------------------------------------------------------------------
# 6. data.json matches the committed measured reports
# ---------------------------------------------------------------------------

def test_data_json_ml_sections_match_measured_reports():
    sys.path.insert(0, str(REPO / "src" / "streaming"))
    try:
        import ml_data  # parses reports/*.md — stdlib only
    finally:
        sys.path.pop(0)

    expected = ml_data.build()
    assert expected, "ml_data.build() returned nothing — reports/ missing or renamed?"
    doc = json.loads((DASH / "data.json").read_text(encoding="utf-8"))
    ml = doc.get("ml") or {}
    stale = [k for k, v in expected.items() if ml.get(k) != v]
    assert not stale, (
        f"data.json ml.{stale} is out of date with reports/ (ml_data.py) — "
        f"re-run the streaming replay/emit to regenerate dashboard/data.json"
    )
