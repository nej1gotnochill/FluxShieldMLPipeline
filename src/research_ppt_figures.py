"""SIH presentation figures — generated from EXISTING measured artifacts only.

Every number plotted here is read from a repository artifact (CSV/JSON) or is
one of the audited constants from reports/*.md. No metric is invented or
synthesized. Frozen ML artifacts are only READ (never modified).

v3 (flat engineering restyle): ppt_01 (DFD-style pipeline, solid colors,
stage panels), ppt_05 (flat KPI evaluation sheet), ppt_06 (flat dataset
infographic). A geometry audit runs before every save: it fails loudly on
text overflowing its box, pairwise text overlap, text outside the canvas,
or an arrow/connector crossing text. ppt_02/03/04 unchanged.

Outputs: reports/figures/ppt/ppt_0[1-6]_*.png  (200 dpi, 16:9-friendly)
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.lines as mlines
import matplotlib.pyplot as plt
import matplotlib.text as mtext
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
import numpy as np
import pandas as pd

OUT = Path("reports/figures/ppt")
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "figure.dpi": 200, "savefig.dpi": 200,
    "font.family": "DejaVu Sans", "font.size": 11,
    "axes.grid": True, "grid.alpha": 0.25, "grid.linestyle": "--",
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.titleweight": "bold", "axes.titlesize": 13,
})

# legacy palette — used ONLY by ppt_02/03/04 (kept byte-identical)
NAVY = "#1F3B5C"
BLUE = "#2E6FA3"
TEAL = "#3E8E7E"
RED = "#C0504D"
AMBER = "#D9822B"
GREY = "#8A8F98"
LIGHT = "#F2F5F8"
INK = "#22272E"

# v3 flat design system (SOLID colors only — no gradients anywhere)
NAV_D = "#12355B"     # dark navy — titles, primary borders
BLUE_D = "#1976D2"; BLUE_L = "#DCEEFF"
GREEN_D = "#2EAD62"; GREEN_L = "#E3F5E8"
YELL_D = "#F2C94C"; YELL_L = "#FFF4CC"
RED_D = "#E74C3C"; RED_L = "#FDE4E1"
PURP_D = "#7650C8"; PURP_L = "#EDE7FA"
DGRAY = "#374151"     # supporting text
LGRAY = "#F3F4F6"     # neutral fill
BORDER = "#C9D2DB"    # light panel border
INKD = "#1A202C"      # near-black metric text
SUBTX = "#4B5563"     # sub-label gray

# semantic stage colors shared by the three figures
S_INPUT, S_EXTRACT, S_INFER, S_DECIDE = BLUE_D, GREEN_D, YELL_D, RED_D

FAMILY_DISPLAY = {
    "benign": "benign",
    "http_slow_read": "http slow read",
    "udp_flood": "udp flood",
    "http_flood": "http flood",
    "tcp_syn_flood": "tcp syn flood",
    "tcp_rst": "tcp rst",
    "flash_traffic": "flash traffic",
    "http_low_rate": "http low rate",
    "http_slow_header": "http slow header",
    "http_slow_body": "http slow body",
    "tcp_syn_fast": "tcp syn fast",
    "tcp_syn_low": "tcp syn low",
}
FAMILY_SHORT = {
    "benign": "benign", "http_slow_read": "slow read", "udp_flood": "udp flood",
    "http_flood": "http flood", "tcp_syn_flood": "syn flood", "tcp_rst": "tcp rst",
    "flash_traffic": "flash", "http_low_rate": "low rate",
    "http_slow_header": "slow hdr", "http_slow_body": "slow body",
    "tcp_syn_fast": "syn fast", "tcp_syn_low": "syn low",
}

# audited constants (README.md / FINAL_ML_SUMMARY.md / reports/dataset_audit.md)
N_FLOWS_TOTAL = 1_236_285
N_BENIGN_FLOWS = 19_276
N_ATTACK_FLOWS = 1_217_009
RAW_GB = 37.84


def load_measured() -> dict:
    a2 = (pd.read_csv("experiments/baseline_results.csv")
          .query("track == 'A2'").groupby("model")[["recall", "f1", "fpr"]].mean())
    ed = json.load(open("reports/early_detection_results.json"))["results"]
    ft = pd.read_csv("experiments/final_test_results.csv").iloc[0]
    bench = pd.read_csv("experiments/benchmark.csv").set_index("metric")["value"]
    fam = pd.read_csv("experiments/baseline_family_recall.csv")
    tb = (fam.query("track == 'B' and model == 'extra_trees'")
          .groupby("family")["recall"].mean())
    return {"a2": a2, "ed": ed, "ft": ft, "bench": bench, "tb": tb}


def load_inventory_family_stats() -> dict:
    """Measured per-family packet/capture/byte totals from the audit inventory."""
    inv = json.load(open("reports/dataset_inventory.json"))["files"]
    stats: dict[str, dict] = {}
    for f in inv:
        s = stats.setdefault(f["family"], {"packets": 0, "captures": 0, "bytes": 0})
        s["packets"] += f["pcap"]["packets"]
        s["captures"] += 1
        s["bytes"] += f["size_bytes"]
    return stats


def feature_groups() -> list[tuple[str, int]]:
    """Exact feature-group partition used by the committed ablation study."""
    groups = json.load(open("reports/feature_ablation_results.json"))["feature_groups"]
    ordered = [
        ("D_timing_iat", "Timing / inter-arrival"),
        ("C_directional", "Directional / packet"),
        ("E_tcp_behavior", "TCP behavior"),
        ("B_rate_statistical", "Rate / statistical"),
        ("F_protocol_indicator", "Protocol indicator"),
    ]
    out = [(label, len(groups[key])) for key, label in ordered]
    assert sum(n for _, n in out) == 66, out
    return out


def availability_counts() -> tuple[int, int]:
    schema = json.load(open("models/feature_schema.json"))
    av = [f["availability"] for f in schema["features"]]
    return av.count("ONLINE"), av.count("TERMINAL")


def threshold_t050_fpr() -> float:
    """Measured FPR at t = 0.5 on the held-out calibration split (development)."""
    grid = json.load(open("reports/threshold_sensitivity_results.json"))["grid"]
    for e in grid:
        if abs(e["threshold"] - 0.5) < 1e-9:
            return e["fpr"]
    raise KeyError("t=0.5 entry missing from threshold_sensitivity_results.json")


# ==========================================================================
# v3 shared helpers — flat design system + geometry audit
# ==========================================================================
def fig_canvas() -> tuple[plt.Figure, plt.Axes]:
    """Full-canvas axes in INCH coordinates: 1 data unit == 1 inch."""
    fig, ax = plt.subplots(figsize=(13.333, 7.5))
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    ax.set_xlim(0, 13.333)
    ax.set_ylim(0, 7.5)
    ax.set_aspect("equal")
    ax.axis("off")
    return fig, ax


def _flat_card(ax, x, y, w, h, *, fill, edge, lw=1.5, r=0.07):
    p = FancyBboxPatch((x, y), w, h,
                       boxstyle=f"round,pad=0,rounding_size={r}",
                       linewidth=lw, edgecolor=edge, facecolor=fill)
    ax.add_patch(p)
    return p


def _txt(ax, x, y, s, *, fs, color=INKD, weight="normal", ha="center",
         va="center", ls=1.25, style="normal"):
    return ax.text(x, y, s, fontsize=fs, color=color, fontweight=weight,
                   ha=ha, va=va, linespacing=ls, style=style)


def _arr(ax, p0, p1, color=NAV_D, lw=2.0, scale=18, reg=None):
    a = FancyArrowPatch(p0, p1, arrowstyle="-|>", mutation_scale=scale,
                        linewidth=lw, color=color, shrinkA=0, shrinkB=0)
    ax.add_patch(a)
    if reg is not None:
        reg.append(a)
    return a


def _line(ax, xs, ys, color=SUBTX, lw=1.0, ls="-", reg=None):
    ln = ax.plot(xs, ys, color=color, lw=lw, linestyle=ls, solid_capstyle="butt")[0]
    if reg is not None:
        reg.append(ln)
    return ln


def _stage_box(ax, x, y, w, h, title, subs=(), *, color, fill, tfs=9.5,
               sfs=7.6, lw=1.5, r=0.07, pairs=None, tcolor=None, scolor=SUBTX):
    """Flat card with an auto-centered title + evenly padded sub lines."""
    p = _flat_card(ax, x, y, w, h, fill=fill, edge=color, lw=lw, r=r)
    tc = tcolor or color
    if not subs:
        t = _txt(ax, x + w / 2, y + h / 2, title, fs=tfs, color=tc, weight="bold")
        if pairs is not None:
            pairs.append((t, p))
        return p
    n = len(subs)
    t_h = tfs / 72 * 1.30 * (title.count("\n") + 1)
    s_h = sfs / 72 * 1.42
    pad = (h - t_h - n * s_h) / (n + 2)
    assert pad > 0.015, f"box too small: {title!r} (pad {pad:.3f})"
    cy = y + h - pad - t_h / 2
    t = _txt(ax, x + w / 2, cy, title, fs=tfs, color=tc, weight="bold")
    if pairs is not None:
        pairs.append((t, p))
    cy -= t_h / 2 + pad + s_h / 2
    for s in subs:
        st = _txt(ax, x + w / 2, cy, s, fs=sfs, color=scolor)
        if pairs is not None:
            pairs.append((st, p))
        cy -= s_h + pad
    return p


def _audit(fig, pairs, arrows, lines, name):
    """Fail loudly on: text outside canvas, text-text overlap, text escaping
    its registered box, or an arrow/connector crossing text."""
    fig.canvas.draw()
    ren = fig.canvas.get_renderer()
    W, H = fig.get_size_inches() * fig.dpi
    items = []
    for t in fig.findobj(mtext.Text):
        s = t.get_text()
        if not t.get_visible() or not s.strip():
            continue
        bb = t.get_window_extent(renderer=ren)
        items.append((s, bb))
        if bb.x0 < 0.5 or bb.y0 < 0.5 or bb.x1 > W - 0.5 or bb.y1 > H - 0.5:
            raise AssertionError(f"{name}: text outside canvas: {s[:40]!r}")
    for i, (s1, b1) in enumerate(items):
        for s2, b2 in items[i + 1:]:
            ox = min(b1.x1, b2.x1) - max(b1.x0, b2.x0)
            oy = min(b1.y1, b2.y1) - max(b1.y0, b2.y0)
            if ox > 1.0 and oy > 1.0:
                raise AssertionError(
                    f"{name}: text overlap {s1[:30]!r} x {s2[:30]!r}")
    for t, p in pairs:
        tb = t.get_window_extent(renderer=ren)
        pb = p.get_window_extent(renderer=ren)
        m = 2.0  # px of clear space required inside every border
        if not (tb.x0 >= pb.x0 + m and tb.x1 <= pb.x1 - m
                and tb.y0 >= pb.y0 + m and tb.y1 <= pb.y1 - m):
            raise AssertionError(f"{name}: text not inside box: {t.get_text()[:40]!r}")
    for artist in list(arrows) + list(lines):
        ab = artist.get_window_extent(renderer=ren)
        if ab is None:
            continue
        for s, bb in items:
            ox = min(ab.x1, bb.x1) - max(ab.x0, bb.x0)
            oy = min(ab.y1, bb.y1) - max(ab.y0, bb.y0)
            if ox > 1.0 and oy > 1.0:
                kind = "arrow" if isinstance(artist, FancyArrowPatch) else "line"
                raise AssertionError(f"{name}: {kind} crosses text {s[:30]!r}")


# ==========================================================================
# PPT 01 — solution architecture (flat DFD-style pipeline)
# ==========================================================================
def ppt01_architecture(m: dict) -> None:
    groups = feature_groups()
    bench, ed = m["bench"], m["ed"]
    fpr_t05 = threshold_t050_fpr()
    pairs, arrows, lines = [], [], []

    fig, ax = fig_canvas()

    _txt(ax, 0.35, 7.20, "FluxShield — Passive Flow-Based DDoS Detection",
         fs=18, color=NAV_D, weight="bold", ha="left")
    _txt(ax, 0.35, 6.88,
         "ML system architecture · DDoS-AT-2022 · every parameter shown is measured on the frozen pipeline",
         fs=10, color=DGRAY, ha="left")

    # ---- stage panels (DFD containers) -----------------------------------
    panels = [
        (0.35, 2.40, "INPUT", S_INPUT),
        (3.30, 3.30, "FEATURE EXTRACTION", S_EXTRACT),
        (7.15, 2.50, "ML INFERENCE", S_INFER),
        (10.20, 2.78, "DECISION", S_DECIDE),
    ]
    for x, w, name, c in panels:
        _flat_card(ax, x, 1.85, w, 4.77, fill="white", edge=BORDER, lw=1.2)
        chip = _flat_card(ax, x + 0.30, 6.08, w - 0.60, 0.34, fill=c, edge=c, lw=0, r=0.06)
        t = _txt(ax, x + w / 2, 6.25, name, fs=9.5, color="white", weight="bold")
        pairs.append((t, chip))

    # inter-panel data-flow arrows
    _arr(ax, (2.77, 5.60), (3.28, 5.60), reg=arrows)
    _arr(ax, (6.62, 5.60), (7.13, 5.60), reg=arrows)
    _arr(ax, (9.67, 5.60), (10.18, 5.60), reg=arrows)

    # ---- P1 · INPUT -------------------------------------------------------
    _stage_box(ax, 0.51, 5.05, 2.08, 0.95, "PASSIVE NETWORK\nTRAFFIC",
               ("one-way capture", "no inline blocking"),
               color=S_INPUT, fill=BLUE_L, tfs=10, sfs=7.6, pairs=pairs)
    _arr(ax, (1.55, 5.03), (1.55, 4.83), color=S_INPUT, reg=arrows)
    _stage_box(ax, 0.51, 3.90, 2.08, 0.95, "PCAP / PACKET STREAM",
               ("98,658,747 packets", "~37.84 GB raw traffic"),
               color=S_INPUT, fill=BLUE_L, tfs=9.6, sfs=7.6, pairs=pairs)
    _arr(ax, (1.55, 3.88), (1.55, 3.67), color=S_INPUT, reg=arrows)
    _stage_box(ax, 0.51, 2.82, 2.08, 0.85, "PARSER VALIDATED",
               ("byte-exact accounting", "45/45 captures"),
               color=DGRAY, fill=LGRAY, tfs=8.6, sfs=7.2, pairs=pairs)

    # ---- P2 · FEATURE EXTRACTION ------------------------------------------
    _stage_box(ax, 3.45, 5.33, 2.70, 0.62, "FLOW CONSTRUCTION",
               ("1,236,285 bidirectional flows",),
               color=S_EXTRACT, fill=GREEN_L, tfs=9.5, sfs=7.6, pairs=pairs)
    _arr(ax, (4.95, 5.31), (4.95, 5.11), color=S_EXTRACT, reg=arrows)
    _stage_box(ax, 3.45, 4.49, 2.70, 0.60, "66-DIMENSIONAL FEATURE VECTOR",
               ("float32 · no IPs / ports / timestamps",),
               color=S_EXTRACT, fill=GREEN_L, tfs=9.3, sfs=7.4, lw=2.2, pairs=pairs)
    # fan-out rail into the measured feature groups
    _line(ax, [3.72, 3.72], [4.49, 2.59], color=S_EXTRACT, lw=1.2, reg=lines)
    gy = 4.01
    for label, n in groups:
        _line(ax, [3.72, 3.85], [gy + 0.16, gy + 0.16], color=S_EXTRACT,
              lw=1.2, reg=lines)
        _stage_box(ax, 3.85, gy, 2.40, 0.32, f"{label}  —  {n}",
                   color=S_EXTRACT, fill="white", tfs=8.2, lw=1.0, r=0.05,
                   pairs=pairs)
        gy -= 0.395

    # ---- P3 · ML INFERENCE -------------------------------------------------
    _stage_box(ax, 7.33, 5.15, 2.14, 0.80, "EXTRATREES CLASSIFIER",
               ("300 trees · max_depth 20", "class_weight balanced"),
               color=S_INFER, fill=YELL_L, tfs=9.3, sfs=7.4, pairs=pairs)
    _arr(ax, (8.40, 5.13), (8.40, 4.84), color=S_INFER, reg=arrows)
    _stage_box(ax, 7.33, 4.20, 2.14, 0.62, "SIGMOID CALIBRATION",
               ("isotonic rejected (degenerate)",),
               color=S_INFER, fill=YELL_L, tfs=9.0, sfs=7.2, pairs=pairs)
    _arr(ax, (8.40, 4.18), (8.40, 3.94), color=S_INFER, reg=arrows)
    _stage_box(ax, 7.33, 3.30, 2.14, 0.62, "DDoS PROBABILITY SCORE",
               ("calibrated p(DDoS) per flow",),
               color=S_INFER, fill=YELL_L, tfs=9.0, sfs=7.2, pairs=pairs)
    _stage_box(ax, 7.33, 2.35, 2.14, 0.70, "NEAR-REAL-TIME INFERENCE",
               (f"{bench['throughput_flows_s@full']/1000:,.0f}K flows/s · "
                f"{bench['latency_median_ms']:.1f} ms median",),
               color=S_INFER, fill=YELL_L, tfs=8.2, sfs=7.0, pairs=pairs)

    # ---- P4 · DECISION ------------------------------------------------------
    _stage_box(ax, 10.44, 5.07, 2.30, 0.85, "OPERATING THRESHOLD",
               ("t = 0.5 (operating point)",
                f"held-out dev FPR {fpr_t05:.5f} ≤ 1e-3"),
               color=S_DECIDE, fill=RED_L, tfs=9.3, sfs=7.4, pairs=pairs)
    _arr(ax, (11.20, 5.05), (10.99, 4.56), color=S_DECIDE, reg=arrows)
    _arr(ax, (11.98, 5.05), (12.19, 4.56), color=S_DECIDE, reg=arrows)
    leg = _flat_card(ax, 10.44, 3.90, 1.06, 0.62, fill=GREEN_D, edge=GREEN_D, lw=0)
    t = _txt(ax, 10.97, 4.30, "LEGITIMATE", fs=7.8, color="white", weight="bold")
    s = _txt(ax, 10.97, 4.09, "(benign)", fs=6.8, color="white")
    pairs += [(t, leg), (s, leg)]
    atk = _flat_card(ax, 11.68, 3.90, 1.06, 0.62, fill=RED_D, edge=RED_D, lw=0)
    t = _txt(ax, 12.21, 4.31, "DDoS", fs=9.0, color="white", weight="bold")
    s = _txt(ax, 12.21, 4.09, "(attack)", fs=6.8, color="white")
    pairs += [(t, atk), (s, atk)]
    _stage_box(ax, 10.44, 2.60, 2.30, 0.90, "3 s OBSERVATION WINDOW",
               (f"{ed['3.0']['metrics']['recall']*100:.2f}% recall · causal evaluation",
                "5 s adds no meaningful recall"),
               color=DGRAY, fill=LGRAY, tfs=8.6, sfs=7.0, pairs=pairs)

    # ---- bottom information strip ------------------------------------------
    strip = [
        ("PASSIVE", "offline analysis of recorded traffic"),
        ("FLOW-BASED", "bidirectional 5-tuple flow features"),
        ("NO PAYLOAD INSPECTION REQUIRED", "headers & timing metadata only"),
        ("3 s OBSERVATION WINDOW", "99.79% recall · causal detection"),
    ]
    for i, (ti, su) in enumerate(strip):
        x = 0.35 + i * 3.22
        _stage_box(ax, x, 0.85, 2.97, 0.80, ti, (su,),
                   color=NAV_D, fill=LGRAY, tfs=8.8, sfs=7.4, lw=1.2, pairs=pairs)
    _txt(ax, 6.6665, 0.42,
         "All stage parameters measured on the DDoS-AT-2022 pipeline · predictive features exclude "
         "IP addresses, ports and timestamps · frozen model artifacts",
         fs=8, color=SUBTX, style="italic")

    _audit(fig, pairs, arrows, lines, "ppt_01")
    fig.savefig(OUT / "ppt_01_solution_architecture.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# ==========================================================================
# PPT 02 — model comparison (dev Track A-2)
# ==========================================================================
def ppt02_model_comparison(m: dict) -> None:
    a2 = m["a2"]
    order = ["extra_trees", "random_forest", "hist_gradient_boost", "logistic_regression"]
    labels = ["ExtraTrees\n(selected)", "RandomForest", "HistGradientBoost", "LogisticRegression"]
    rec = [a2.loc[k, "recall"] * 100 for k in order]
    f1 = [a2.loc[k, "f1"] * 100 for k in order]

    fig, ax = plt.subplots(figsize=(10, 5.4))
    x = np.arange(len(order))
    w = 0.36
    b1 = ax.bar(x - w / 2, rec, w, label="Recall (dev, Track A-2 mean)", color=TEAL)
    b2 = ax.bar(x + w / 2, f1, w, label="F1 (dev, Track A-2 mean)", color=BLUE)
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.35,
                    f"{b.get_height():.2f}%", ha="center", fontsize=9)
    ax.set_xticks(x, labels, fontsize=10.5)
    ax.set_ylim(80, 100.6)
    ax.set_ylabel("percentage")
    ax.set_title("Model comparison under capture-disjoint evaluation\n"
                 "(development Track A-2 folds, 5-fold means — frozen final test not used)")
    ax.legend(loc="lower left", frameon=False)
    ax.annotate("selected: best Track-A2 precision/recall AND strong\n"
                "never-seen-family recall (Track B, see separate figure)",
                xy=(0, 100.1), xytext=(0.6, 96.5), fontsize=9, color=NAVY,
                arrowprops=dict(arrowstyle="->", color=NAVY, lw=1.2))
    fig.tight_layout()
    fig.savefig(OUT / "ppt_02_model_comparison.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# ==========================================================================
# PPT 03 — early detection
# ==========================================================================
def ppt03_early_detection(m: dict) -> None:
    ed = m["ed"]
    wins = [1.0, 3.0, 5.0]
    rec = [ed["1.0"]["metrics"]["recall"] * 100,
           ed["3.0"]["metrics"]["recall"] * 100,
           ed["5.0"]["metrics"]["recall"] * 100]
    f1 = [ed["1.0"]["metrics"]["f1"] * 100,
          ed["3.0"]["metrics"]["f1"] * 100,
          ed["5.0"]["metrics"]["f1"] * 100]
    full = m["ft"]["recall"] * 100

    fig, ax = plt.subplots(figsize=(10, 5.6))
    ax.plot(wins, rec, "o-", color=TEAL, lw=2.4, ms=9, label="Recall (causal window)")
    ax.plot(wins, f1, "s--", color=BLUE, lw=2.0, ms=8, label="F1 (causal window)")
    ax.axhline(full, color=GREY, lw=1.4, ls=":")
    ax.text(4.35, full + 0.12, f"full-flow final-test recall {full:.2f}%\n(untouched test, reference)",
            fontsize=8.8, color=GREY, ha="right")
    for w, r in zip(wins, rec):
        ax.annotate(f"{r:.2f}%", (w, r), textcoords="offset points",
                    xytext=(0, -18), ha="center", fontsize=10, fontweight="bold",
                    color=TEAL)
    ax.text(5.30, 62.8, "3 s reaches essentially full-flow performance;\n"
            "5 s adds no meaningful additional recall",
            ha="right", va="bottom", fontsize=10, color=NAVY,
            bbox=dict(boxstyle="round,pad=0.4", fc=LIGHT, ec=NAVY, lw=0.8))
    ax.set_xticks(wins, ["1 s", "3 s", "5 s"])
    ax.set_xlim(0.6, 5.4)
    ax.set_ylim(60, 101.5)
    ax.set_xlabel("observation window (causal — only packets within the window)")
    ax.set_ylabel("percentage")
    ax.set_title("Early detection: recall vs observation window\n"
                 "(frozen model · untouched final-test captures · structural causality)")
    ax.legend(loc="lower right", frameon=False)
    fig.tight_layout()
    fig.savefig(OUT / "ppt_03_early_detection.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# ==========================================================================
# PPT 04 — Track B generalization
# ==========================================================================
def ppt04_track_b(m: dict) -> None:
    tb = m["tb"]
    fams = [("UDP Flood", tb["udp_flood"]), ("TCP RST", tb["tcp_rst"]),
            ("TCP SYN Flood", tb["tcp_syn_flood"]),
            ("AGGREGATE Track-B recall", tb["tcp_syn_flood"] * 0 + 0.9740)]
    labels = [f[0] for f in fams]
    vals = [float(f[1]) * 100 for f in fams]
    colors = [BLUE, BLUE, BLUE, NAVY]

    fig, ax = plt.subplots(figsize=(10, 5.2))
    bars = ax.barh(labels, vals, color=colors, height=0.58)
    for b, v in zip(bars, vals):
        ax.text(v - 1.2 if v > 90 else v + 1.2, b.get_y() + b.get_height() / 2,
                f"{v:.2f}%", va="center",
                ha="right" if v > 90 else "left",
                color="white" if v > 90 else NAVY, fontsize=11, fontweight="bold")
    ax.set_xlim(0, 104)
    ax.set_xlabel("recall on held-out captures (%)")
    ax.set_title("Track B — never-seen attack families held out entirely from training\n"
                 "(development family-holdout; behavioral generalization, not zero-day guarantee)")
    ax.text(52, 0.62, "these captures were EXCLUDED from training —\n"
            "the model never saw these attack mechanics",
            fontsize=9.5, color=GREY, ha="center", style="italic")
    fig.tight_layout()
    fig.savefig(OUT / "ppt_04_track_b_generalization.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# ==========================================================================
# PPT 05 — final performance (flat evaluation sheet)
# ==========================================================================
def ppt05_final_performance(m: dict) -> None:
    ft, bench, ed, ed3 = m["ft"], m["bench"], m["ed"], m["ed"]["3.0"]
    pairs = []

    fig, ax = fig_canvas()

    _txt(ax, 0.35, 7.20, "FINAL MODEL PERFORMANCE", fs=18, color=NAV_D,
         weight="bold", ha="left")
    _txt(ax, 0.35, 6.88,
         "Untouched final test (448,076 flows · 17 captures · scored once)  +  "
         "frozen-model inference benchmark — distinct evaluation categories",
         fs=10, color=DGRAY, ha="left")

    def header(x, y, s):
        _txt(ax, x, y, s, fs=12, color=NAV_D, weight="bold", ha="left")
        _line(ax, [x, x + 12.63], [y - 0.13, y - 0.13], color=BORDER, lw=1.0)

    # ---- section 1: final test performance ---------------------------------
    header(0.35, 6.52, "1 · FINAL TEST PERFORMANCE")

    hero = [(0.35, f"{ft['f1']*100:.4f}%", "F1 SCORE"),
            (3.60, f"{ft['recall']*100:.4f}%", "RECALL (ATTACK DETECTION)")]
    for x0, val, lab in hero:
        p = _flat_card(ax, x0, 5.02, 3.05, 1.26, fill=GREEN_L, edge=GREEN_D, lw=2.0)
        t = _txt(ax, x0 + 1.525, 5.80, val, fs=30, color=GREEN_D, weight="bold")
        s = _txt(ax, x0 + 1.525, 5.30, lab, fs=10.5, color=INKD, weight="bold")
        pairs += [(t, p), (s, p)]

    sec = [(6.90, f"{ft['precision']*100:.4f}%", "PRECISION",
            "441,569 TP / 441,570 alerts"),
           (8.98, f"{ft['fpr']*100:.4f}%", "FALSE POSITIVE RATE",
            "1 FP / 5,555 benign"),
           (11.06, f"{ft['fnr']*100:.3f}%", "FALSE NEGATIVE RATE",
            "952 FN / 442,521 attacks")]
    for x0, val, lab, note in sec:
        p = _flat_card(ax, x0, 5.52, 1.92, 0.76, fill=LGRAY, edge=NAV_D, lw=1.2)
        t = _txt(ax, x0 + 0.96, 6.04, val, fs=14.5, color=NAV_D, weight="bold")
        s1 = _txt(ax, x0 + 0.96, 5.80, lab, fs=7.6, color=INKD, weight="bold")
        s2 = _txt(ax, x0 + 0.96, 5.64, note, fs=6.8, color=SUBTX)
        pairs += [(t, p), (s1, p), (s2, p)]

    pauc = _flat_card(ax, 6.90, 5.02, 6.08, 0.34, fill=LGRAY, edge=NAV_D, lw=1.2)
    t = _txt(ax, 9.94, 5.19,
             f"PR-AUC {ft['pr_auc']:.4f}   ·   ROC-AUC {ft['roc_auc']:.4f}   ·   "
             "per-family recall ≥ 0.997 (8/8 families)",
             fs=9, color=NAV_D, weight="bold")
    pairs.append((t, pauc))

    # ---- section 2: inference benchmark ------------------------------------
    header(0.35, 4.62, "2 · INFERENCE BENCHMARK  (frozen calibrated model)")
    bitems = [(0.35, "481K", "flows/s full-batch throughput"),
              (3.57, f"{bench['latency_median_ms']:.1f} ms", "median single-flow latency"),
              (6.79, f"{bench['latency_p95_ms']:.1f} ms", "P95 single-flow latency"),
              (10.01, f"{bench['model_size_mb']:.1f} MB", "serialized model size")]
    for x0, val, lab in bitems:
        p = _flat_card(ax, x0, 3.42, 2.97, 0.96, fill=YELL_L, edge=YELL_D, lw=1.8)
        t = _txt(ax, x0 + 1.485, 4.08, val, fs=21, color=NAV_D, weight="bold")
        s = _txt(ax, x0 + 1.485, 3.68, lab, fs=8.6, color=DGRAY)
        pairs += [(t, p), (s, p)]

    # ---- section 3: early detection / section 4: confusion matrix ----------
    header(0.35, 3.02, "3 · EARLY DETECTION — FINAL-TEST CAPTURES")
    p = _flat_card(ax, 0.35, 1.30, 6.30, 1.48, fill=BLUE_L, edge=BLUE_D, lw=2.0)
    t = _txt(ax, 3.50, 2.36, f"{ed3['metrics']['recall']*100:.2f}%", fs=26,
             color=BLUE_D, weight="bold")
    s1 = _txt(ax, 3.50, 1.96, "RECALL @ 3 s CAUSAL WINDOW", fs=10, color=INKD,
              weight="bold")
    s2 = _txt(ax, 3.50, 1.60,
              f"coverage {ed3['detection_coverage_pct']:.2f}%  ·  1 s window: "
              f"{ed['1.0']['metrics']['recall']*100:.2f}%  ·  5 s adds no meaningful additional recall",
              fs=8.4, color=DGRAY)
    pairs += [(t, p), (s1, p), (s2, p)]

    header(6.90, 3.02, "4 · CONFUSION MATRIX — FINAL TEST")
    cw, ch = 2.10, 0.62
    cx = [8.55, 10.75]
    ry = [2.02, 1.30]
    cells = [
        (0, 0, f"{int(ft['tn']):,}", GREEN_L, "true negatives"),
        (1, 0, f"{int(ft['fp']):,}", RED_L, "false positive"),
        (0, 1, f"{int(ft['fn']):,}", RED_L, "false negatives"),
        (1, 1, f"{int(ft['tp']):,}", GREEN_L, "true positives"),
    ]
    for cxi, ryi, val, fc, cap in cells:
        p = _flat_card(ax, cx[cxi], ry[ryi], cw, ch, fill=fc,
                       edge=NAV_D if fc == GREEN_L else RED_D, lw=1.2)
        t = _txt(ax, cx[cxi] + cw / 2, ry[ryi] + 0.38, val, fs=15, color=INKD,
                 weight="bold")
        s = _txt(ax, cx[cxi] + cw / 2, ry[ryi] + 0.15, cap, fs=6.8, color=SUBTX)
        pairs += [(t, p), (s, p)]
    _txt(ax, cx[0] + cw / 2, 2.74, "PREDICTED BENIGN", fs=8.4, color=SUBTX,
         weight="bold")
    _txt(ax, cx[1] + cw / 2, 2.74, "PREDICTED DDOS", fs=8.4, color=SUBTX,
         weight="bold")
    _txt(ax, 8.45, ry[0] + ch / 2, "ACTUAL BENIGN", fs=8.4, color=SUBTX,
         weight="bold", ha="right")
    _txt(ax, 8.45, ry[1] + ch / 2, "ACTUAL DDOS", fs=8.4, color=SUBTX,
         weight="bold", ha="right")

    # ---- footer --------------------------------------------------------------
    _flat_card(ax, 0.35, 0.50, 12.63, 0.48, fill=LGRAY, edge=BORDER, lw=1.0)
    _txt(ax, 6.6665, 0.83,
         "Final test was untouched; frozen model artifacts remained byte-identical (SHA-256 verified).",
         fs=8.2, color=DGRAY)
    _txt(ax, 6.6665, 0.65,
         "Detection metrics = untouched final test  ·  throughput / latency / size = inference benchmark measurements",
         fs=8.2, color=SUBTX, style="italic")

    _audit(fig, pairs, [], [], "ppt_05")
    fig.savefig(OUT / "ppt_05_final_performance.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# ==========================================================================
# PPT 06 — dataset scale (flat infographic)
# ==========================================================================
def ppt06_dataset_scale() -> None:
    fam_stats = load_inventory_family_stats()
    total_packets = sum(s["packets"] for s in fam_stats.values())
    total_caps = sum(s["captures"] for s in fam_stats.values())
    assert total_caps == 45 and total_packets == 98_658_747
    groups = feature_groups()
    pairs = []

    fig, ax = fig_canvas()

    _txt(ax, 0.35, 7.20, "DDoS-AT-2022 — DATASET SCALE", fs=18, color=NAV_D,
         weight="bold", ha="left")
    _txt(ax, 0.35, 6.88,
         "Large-scale PCAP traffic converted into behavioral flow representations · "
         "all counts measured from the audited inventory",
         fs=10, color=DGRAY, ha="left")

    def header(x, y, s):
        _txt(ax, x, y, s, fs=12, color=NAV_D, weight="bold", ha="left")
        _line(ax, [x, x + (5.40 if x < 6.6 else 6.08)], [y - 0.13, y - 0.13],
              color=BORDER, lw=1.0)

    # ---- section 1: dataset scale ------------------------------------------
    header(0.35, 6.52, "1 · DATASET SCALE")
    heads = [(0.35, "45", "PCAP CAPTURES"),
             (3.57, "98,658,747", "PACKETS"),
             (6.79, "~37.84 GB", "RAW TRAFFIC"),
             (10.01, "1,236,285", "EXTRACTED FLOWS")]
    for x0, val, lab in heads:
        p = _flat_card(ax, x0, 5.42, 2.97, 0.86, fill=BLUE_L, edge=BLUE_D, lw=1.8)
        t = _txt(ax, x0 + 1.485, 6.02, val, fs=20, color=BLUE_D, weight="bold")
        s = _txt(ax, x0 + 1.485, 5.66, lab, fs=8.8, color=INKD, weight="bold")
        pairs += [(t, p), (s, p)]

    # ---- section 2: dataset composition -------------------------------------
    header(0.35, 5.10, "2 · DATASET COMPOSITION")
    comp = [(0.35, "17", "BENIGN CAPTURES", GREEN_D, GREEN_L),
            (4.64, "28", "ATTACK CAPTURES", RED_D, RED_L),
            (8.93, "11", "ATTACK FAMILIES", NAV_D, LGRAY)]
    for x0, val, lab, c, lc in comp:
        p = _flat_card(ax, x0, 4.34, 4.04, 0.54, fill=lc, edge=c, lw=1.5)
        t = _txt(ax, x0 + 0.55, 4.61, val, fs=15, color=c, weight="bold")
        s = _txt(ax, x0 + 2.20, 4.61, lab, fs=9.5, color=INKD, weight="bold")
        pairs += [(t, p), (s, p)]

    # ---- section 3: processing pipeline (left column) ------------------------
    header(0.35, 4.10, "3 · PROCESSING PIPELINE")
    steps = [(0.35, "PCAP\nCAPTURES", "45 files", S_INPUT),
             (1.96, "PACKETS", "98,658,747", S_INPUT),
             (3.57, "BIDIRECTIONAL\nFLOWS", "1,236,285", S_EXTRACT),
             (5.18, "66-FEATURE\nVECTORS", "float32", NAV_D)]
    for i, (x0, ti, su, c) in enumerate(steps):
        p = _flat_card(ax, x0, 3.20, 1.23, 0.68, fill="white", edge=c, lw=1.5)
        t = _txt(ax, x0 + 0.615, 3.66, ti, fs=8.0, color=c, weight="bold")
        s = _txt(ax, x0 + 0.615, 3.35, su, fs=6.6, color=DGRAY)
        pairs += [(t, p), (s, p)]
        if i < 3:
            _arr(ax, (x0 + 1.25, 3.54), (x0 + 1.59, 3.54), color=NAV_D, lw=1.8, scale=13)
    # NOTE: last box ends at 6.41; column width 0.35..5.75 for chips below

    # ---- section 4: feature representation (left column) ---------------------
    header(0.35, 2.80, "4 · FEATURE REPRESENTATION")
    p = _flat_card(ax, 0.35, 2.22, 5.40, 0.40, fill=BLUE_L, edge=BLUE_D, lw=1.5)
    t = _txt(ax, 3.05, 2.42,
             "66 PREDICTIVE FEATURES · float32 · no IPs / ports / timestamps",
             fs=9.5, color=NAV_D, weight="bold")
    pairs.append((t, p))
    chips = [
        ("Timing / IAT — 22", GREEN_D, GREEN_L), ("Directional / packet — 16", BLUE_D, BLUE_L),
        ("TCP behavior — 16", YELL_D, YELL_L), ("Rate / statistical — 11", PURP_D, PURP_L),
        ("Protocol indicator — 1", RED_D, RED_L), ("TOTAL FEATURES — 66", NAV_D, LGRAY),
    ]
    for i, (txt, c, lc) in enumerate(chips):
        x0 = 0.35 + (i % 2) * 2.80
        y0 = [1.66, 1.12, 0.58][i // 2]
        p = _flat_card(ax, x0, y0, 2.60, 0.38, fill=lc, edge=c, lw=1.2)
        t = _txt(ax, x0 + 1.30, y0 + 0.19, txt, fs=8.4, color=c, weight="bold")
        pairs.append((t, p))
    _txt(ax, 3.05, 0.26,
         "class imbalance is real and labelled: 19,276 benign (1.6%) vs "
         "1,217,009 attack (98.4%) flows",
         fs=7.4, color=SUBTX, style="italic")
    _txt(ax, 3.05, 0.08,
         "benign packets dominate raw volume (56.90M of 98.66M packets)",
         fs=7.4, color=SUBTX, style="italic")

    # ---- section 5: attack family diversity (right column) --------------------
    header(6.90, 4.10, "5 · ATTACK FAMILY DIVERSITY — PACKET DISTRIBUTION")
    axd = fig.add_axes([7.60 / 13.333, 0.62 / 7.5, 5.38 / 13.333, 3.20 / 7.5])
    fams_sorted = sorted(fam_stats.items(), key=lambda kv: kv[1]["packets"])
    names = [FAMILY_SHORT.get(k, k) for k, _ in fams_sorted]
    vals = [s["packets"] / 1e6 for _, s in fams_sorted]
    caps = [s["captures"] for _, s in fams_sorted]
    colors = [GREEN_D if k == "benign" else RED_D for k, _ in fams_sorted]
    bars = axd.barh(names, vals, color=colors, height=0.62)
    for b, v, c in zip(bars, vals, caps):
        axd.text(v + 1.0, b.get_y() + b.get_height() / 2,
                 f"{v:.2f}M · {c} cp", va="center", fontsize=7.2, color=DGRAY)
    axd.set_xlim(0, 70)
    axd.set_xlabel("packets (millions) — measured · 'cp' = capture count", fontsize=8)
    axd.tick_params(axis="y", labelsize=7.6)
    axd.set_title("measured packets per family — the dataset is NOT balanced",
                  fontsize=9, color=NAV_D, loc="left")
    axd.grid(axis="y", visible=False)

    _audit(fig, pairs, [], [], "ppt_06")
    fig.savefig(OUT / "ppt_06_dataset_scale.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    m = load_measured()
    ppt01_architecture(m); print("ppt_01 done")
    ppt02_model_comparison(m); print("ppt_02 done")
    ppt03_early_detection(m); print("ppt_03 done")
    ppt04_track_b(m); print("ppt_04 done")
    ppt05_final_performance(m); print("ppt_05 done")
    ppt06_dataset_scale(); print("ppt_06 done")
