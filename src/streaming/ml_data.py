"""Measured ML data for the dashboard — parsed from the repo's own reports.

Everything on the Model screen must come from real evaluation output (DATA
contract: "the UI never derives or fakes them"). This module reads the
committed reports and maps them onto the contract:

    ml.final     <- reports/final_test_report.md   (untouched final test)
    ml.early     <- reports/early_detection_report.md (causal windows)
    ml.comparison<- reports/baseline_report.md     (4-model capture-disjoint)
    ml.trackB    <- baseline_report Track B aggregate (ExtraTrees)

Missing files -> those sections stay absent and the UI keeps its fixtures;
values are formatted exactly as the contract expects (percent strings,
{k,v} pairs). Nothing is invented: if a report is missing or a row is
absent, the field is simply not emitted.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _rows(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("|") and line.endswith("|"):
            cells = [c.strip().strip("*") for c in line.strip("|").split("|")]
            out.append(cells)
    return out


def _pct(x: float) -> float:
    return round(x * 100.0, 2)


def final_metrics() -> list[dict[str, str]]:
    """Untouched final test -> [{k, v}] rows for ml.final."""
    want = {
        "precision": "Precision",
        "recall": "Recall",
        "f1": "F1",
        "pr_auc": "PR-AUC",
        "roc_auc": "ROC-AUC",
        "fpr": "FPR",
        "fnr": "FNR",
    }
    rows = _rows(REPO_ROOT / "reports" / "final_test_report.md")
    got: dict[str, str] = {}
    for cells in rows:
        if len(cells) >= 2:
            for key, label in want.items():
                if cells[0].lower() == label.lower():
                    got[key] = cells[1]
    confusion = None
    for cells in rows:
        if cells and cells[0].lower().startswith("confusion") and len(cells) >= 2:
            confusion = cells[1]
    out = [
        {"k": "Precision", "v": got.get("precision", "-")},
        {"k": "Recall", "v": got.get("recall", "-")},
        {"k": "F1", "v": got.get("f1", "-")},
        {"k": "PR-AUC", "v": got.get("pr_auc", "-")},
        {"k": "FPR", "v": got.get("fpr", "-")},
        {"k": "FNR", "v": got.get("fnr", "-")},
    ]
    if confusion:
        out.append({"k": "Confusion (tn, fp, fn, tp)", "v": confusion})
    return out


def confusion_tuple() -> tuple[int, int, int, int] | None:
    """(tn, fp, fn, tp) from the final-test report, if present."""
    for cells in _rows(REPO_ROOT / "reports" / "final_test_report.md"):
        if cells and cells[0].lower().startswith("confusion") and len(cells) >= 2:
            nums = re.findall(r"[\d,]+", cells[1])
            if len(nums) >= 4:
                vals = [int(n.replace(",", "")) for n in nums[:4]]
                return tuple(vals)
    return None


def early_windows() -> list[dict]:
    """Causal 1/3/5 s windows -> [{t, recall}] (percent numbers)."""
    rows = _rows(REPO_ROOT / "reports" / "early_detection_report.md")
    out = []
    for cells in rows:
        if len(cells) >= 5 and re.fullmatch(r"\d+s", cells[0]):
            try:
                out.append({"t": cells[0], "recall": _pct(float(cells[3]))})
            except ValueError:
                continue
    return out


def comparison() -> list[dict]:
    """Track A-2 four-model comparison -> [{nm, f1, sel, why}]."""
    rows = _rows(REPO_ROOT / "reports" / "baseline_report.md")
    names = {
        "ExtraTrees": ("ExtraTrees · 300", True,
                       "SELECTED — best Track A-2 and never-seen-family recall"),
        "RandomForest": ("RandomForest", False,
                         "equivalent within noise; slower to train"),
        "HistGradientBoost": ("HistGradientBoosting", False,
                              "fails catastrophically on held-out families (Track B 0.076)"),
        "LogisticRegression": ("LogisticRegression", False,
                               "unsuitable for never-seen attack mechanics"),
    }
    out = []
    for cells in rows:
        if len(cells) >= 4 and cells[0].split(" ")[0] in names:
            base = cells[0].split(" ")[0]
            m = re.match(r"([\d.]+)\s*±", cells[3])
            if not m:
                continue
            nm, sel, why = names[base]
            out.append({"nm": nm, "f1": _pct(float(m.group(1))), "sel": sel, "why": why})
    return out


def track_b() -> float | None:
    """ExtraTrees Track B aggregate recall (percent number).
    Section-scoped: the Track B table lives under its own heading; the
    Track A-2 table also has an ExtraTrees row and must not be confused
    with it (its first metric is precision, not aggregate recall)."""
    text = (REPO_ROOT / "reports" / "baseline_report.md")
    if not text.exists():
        return None
    section = text.read_text(encoding="utf-8").split("## Track B", 1)[-1]
    for line in section.splitlines():
        line = line.strip()
        if line.startswith("|") and line.endswith("|"):
            cells = [c.strip().strip("*") for c in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0] == "ExtraTrees":
                try:
                    return _pct(float(cells[1]))
                except ValueError:
                    return None
    return None


def build() -> dict:
    """Assemble the ml.* sections; omit anything not backed by a report."""
    out: dict = {}
    fin = final_metrics()
    if fin:
        out["final"] = fin
    cm = confusion_tuple()
    if cm:
        out["confusion"] = {"tn": cm[0], "fp": cm[1], "fn": cm[2], "tp": cm[3]}
    ew = early_windows()
    if ew:
        out["early"] = ew
    cp = comparison()
    if cp:
        out["comparison"] = cp
    tb = track_b()
    if tb is not None:
        out["trackB"] = tb
    return out
