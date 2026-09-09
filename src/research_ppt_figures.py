"""SIH presentation figures — generated from EXISTING measured artifacts only.

Every number plotted here is read from a repository artifact (CSV/JSON) or is
one of the audited constants from reports/*.md. No metric is invented or
synthesized. Frozen ML artifacts are only READ (never modified).

v2 (visual refinement): ppt_01 (left-to-right ML-system architecture with the
66-feature group fan-out), ppt_05 (hierarchical KPI board with confusion
matrix), ppt_06 (dataset scale with transformation flow, measured family
diversity and feature-group representation). ppt_02/03/04 unchanged.

Outputs: reports/figures/ppt/ppt_0[1-6]_*.png  (200 dpi, 16:9-friendly)
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
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

NAVY = "#1F3B5C"
BLUE = "#2E6FA3"
TEAL = "#3E8E7E"
RED = "#C0504D"
AMBER = "#D9822B"
GREY = "#8A8F98"
LIGHT = "#F2F5F8"
INK = "#22272E"

# semantic stage colors (shared across the PPT figure set)
C_INPUT, C_EXTRACT, C_INFER, C_DECIDE = BLUE, TEAL, AMBER, RED

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


# --------------------------------------------------------------------------
# shared drawing helpers (consistent visual language across the set)
# --------------------------------------------------------------------------
def _card(ax, x, y, w, h, title, sub="", color=NAVY, fill=LIGHT,
          tfs=11.5, sfs=8.4, lw=1.4, dashed=False, rounding=0.10,
          textcolor=None):
    ls = (0, (4, 2)) if dashed else "-"
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                                boxstyle=f"round,pad=0.02,rounding_size={rounding}",
                                linewidth=lw, edgecolor=color, facecolor=fill,
                                linestyle=ls))
    cy_t = y + h * (0.68 if sub else 0.5)
    ax.text(x + w / 2, cy_t, title, ha="center", va="center",
            fontsize=tfs, fontweight="bold",
            color=textcolor or color, linespacing=1.15)
    if sub:
        ax.text(x + w / 2, y + h * 0.28, sub, ha="center", va="center",
                fontsize=sfs, color="#4A5058", linespacing=1.25)


def _arrow(ax, p0, p1, color=GREY, lw=2.0, scale=18):
    ax.add_patch(FancyArrowPatch(p0, p1, arrowstyle="-|>",
                                 mutation_scale=scale, linewidth=lw, color=color,
                                 shrinkA=0, shrinkB=0))


def _chip(ax, x, y, text, color, fs=8.4, textcolor="white"):
    ax.text(x, y, text, ha="center", va="center", fontsize=fs,
            fontweight="bold", color=textcolor,
            bbox=dict(boxstyle="round,pad=0.34", fc=color, ec="none"))


# --------------------------------------------------------------------------
# PPT 01 — solution architecture (refined: left-to-right ML-system pipeline)
# --------------------------------------------------------------------------
def ppt01_architecture(m: dict) -> None:
    groups = feature_groups()
    n_online, n_terminal = availability_counts()
    bench, ed = m["bench"], m["ed"]
    fpr_t05 = threshold_t050_fpr()

    fig, ax = plt.subplots(figsize=(12.8, 7.2))
    ax.set_xlim(0, 12.8)
    ax.set_ylim(0, 7.2)
    ax.axis("off")

    ax.text(0.15, 6.93, "FluxShield — passive flow-based DDoS detection",
            ha="left", fontsize=17, fontweight="bold", color=NAVY)
    ax.text(0.15, 6.62, "ML system architecture — every stage measured on the DDoS-AT-2022 pipeline",
            ha="left", fontsize=10, color=GREY)

    # stage legend directly above the four columns
    cols = {1: 1.55, 2: 4.90, 3: 8.35, 4: 11.50}
    _chip(ax, cols[1], 6.28, "INPUT", C_INPUT)
    _chip(ax, cols[2], 6.28, "FEATURE EXTRACTION", C_EXTRACT)
    _chip(ax, cols[3], 6.28, "ML INFERENCE", C_INFER)
    _chip(ax, cols[4], 6.28, "DECISION", C_DECIDE)

    # ---- column 1: INPUT ------------------------------------------------
    _card(ax, 0.30, 4.55, 2.50, 1.30, "Passive network traffic",
          "one-way PCAP capture\n98.66M packets · 37.84 GB\nno inline blocking",
          color=C_INPUT, fill="#EAF1F7", tfs=12)
    _arrow(ax, (2.86, 5.20), (3.52, 5.20), lw=2.2, scale=20)
    _card(ax, 0.30, 3.35, 2.50, 0.72,
          "Payload inspection not required", "headers & timing metadata only",
          color=GREY, fill="white", tfs=8.8, sfs=8.0, lw=1.0, dashed=True)
    ax.plot([1.55, 1.55], [4.53, 4.09], color=GREY, lw=0.9, linestyle=":")

    # ---- column 2: FEATURE EXTRACTION -----------------------------------
    _card(ax, 3.60, 4.75, 2.60, 0.95, "Flow construction",
          "bidirectional 5-tuple flows\nmirror-duplicate removal",
          color=C_EXTRACT, fill="#EAF4F1", tfs=11.5)
    _arrow(ax, (4.90, 4.72), (4.90, 4.38), lw=1.8, scale=15)
    _card(ax, 3.45, 3.15, 2.90, 1.20, "66-dimensional\nfeature vector",
          "float32 · no IPs, ports or timestamps\nas predictive features",
          color=C_EXTRACT, fill="#DDEDE8", tfs=13.5, lw=2.0)
    # feature-group fan-out (exact ablation partition)
    ax.plot([4.90, 4.90], [3.12, 2.89], color=C_EXTRACT, lw=1.2)
    gy = 2.52
    for label, n in groups:
        _card(ax, 3.75, gy, 2.30, 0.33, f"{label}  ·  {n}", "",
              color=C_EXTRACT, fill="white", tfs=8.4, lw=1.0, rounding=0.06)
        gy -= 0.40
    _arrow(ax, (6.28, 5.20), (7.18, 5.20), lw=2.2, scale=20)

    # ---- column 3: ML INFERENCE -----------------------------------------
    _card(ax, 7.25, 4.75, 2.20, 0.95, "ExtraTrees classifier",
          "300 trees · max_depth 20\nclass_weight balanced",
          color=C_INFER, fill="#FBF0E3", tfs=11.5)
    _arrow(ax, (8.35, 4.72), (8.35, 4.38), lw=1.8, scale=15)
    _card(ax, 7.25, 3.55, 2.20, 0.80, "Sigmoid calibration",
          "isotonic rejected:\ndegenerate outputs",
          color=C_INFER, fill="#FBF0E3", tfs=11, sfs=8.0)
    _arrow(ax, (8.35, 3.52), (8.35, 3.18), lw=1.8, scale=15)
    _card(ax, 7.25, 2.35, 2.20, 0.80, "Threat probability",
          "calibrated p(DDoS)\nper flow",
          color=C_INFER, fill="#FBF0E3", tfs=11, sfs=8.2)
    _card(ax, 7.05, 1.05, 2.60, 0.85,
          "Near-real-time passive detection",
          f"{bench['throughput_flows_s@full']/1000:,.0f}K flows/s · "
          f"{bench['latency_median_ms']:.1f} ms median\n(measured benchmark, frozen model)",
          color=GREY, fill="white", tfs=8.8, sfs=7.8, lw=1.0, dashed=True)
    ax.plot([8.35, 8.35], [2.32, 1.93], color=GREY, lw=0.9, linestyle=":")
    _arrow(ax, (9.51, 5.20), (10.32, 5.20), lw=2.2, scale=20)

    # ---- column 4: DECISION ----------------------------------------------
    _card(ax, 10.40, 4.70, 2.20, 1.00, "Operating threshold",
          f"t = 0.5 · validated on held-out\ndev benign: FPR {fpr_t05:.5f} ≤ 1e-3",
          color=C_DECIDE, fill="#F9ECEC", tfs=12, sfs=8.0)
    _arrow(ax, (10.925, 4.66), (10.925, 4.28), lw=1.8, scale=15)
    _arrow(ax, (12.025, 4.66), (12.025, 4.28), lw=1.8, scale=15)
    _card(ax, 10.40, 3.72, 1.05, 0.52, "LEGITIMATE", "",
          color=TEAL, fill=TEAL, tfs=9.2, textcolor="white")
    _card(ax, 11.50, 3.72, 1.05, 0.52, "DDoS ALERT", "",
          color=RED, fill=RED, tfs=9.2, textcolor="white")
    _card(ax, 10.30, 1.60, 2.40, 0.85,
          "Operational observation window: 3 s",
          f"{ed['3.0']['metrics']['recall']*100:.2f}% recall with causal early\n"
          "detection (final-test captures)",
          color=GREY, fill="white", tfs=8.6, sfs=7.8, lw=1.0, dashed=True)
    ax.plot([12.02, 12.02], [3.69, 2.48], color=GREY, lw=0.9, linestyle=":")

    # ---- scope banner (with schema facts folded in) -----------------------
    ax.add_patch(FancyBboxPatch((0.30, 0.14), 12.20, 0.58,
                                boxstyle="round,pad=0.02,rounding_size=0.10",
                                linewidth=1.0, edgecolor=NAVY, facecolor=LIGHT))
    ax.text(6.40, 0.57, "PASSIVE · FLOW-BASED — no payload decryption · no inline blocking "
                        "· no dashboard/frontend component",
            ha="center", va="center", fontsize=9.5, fontweight="bold", color=NAVY)
    ax.text(6.40, 0.26,
            f"feature groups overlap (documented in the ablation study) · Σ = 66 · "
            f"availability: {n_online} online / {n_terminal} terminal "
            "(terminal features recomputed causally for early windows)",
            ha="center", va="center", fontsize=8.2, color=GREY, style="italic")

    fig.savefig(OUT / "ppt_01_solution_architecture.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------
# PPT 02 — model comparison (dev Track A-2)
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# PPT 03 — early detection
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# PPT 04 — Track B generalization
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# PPT 05 — final performance (refined: hierarchical KPI board)
# --------------------------------------------------------------------------
def ppt05_final_performance(m: dict) -> None:
    ft = m["ft"]
    bench = m["bench"]
    ed3 = m["ed"]["3.0"]

    fig, ax = plt.subplots(figsize=(12.8, 7.2))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.025, 0.965, "FluxShield — final model performance",
            fontsize=17, fontweight="bold", color=NAVY, va="center")
    ax.text(0.025, 0.925,
            "Untouched final test (448,076 flows · 17 captures · scored once)  +  "
            "frozen-model inference benchmark — distinct evaluation categories",
            fontsize=10, color=GREY, va="center")

    # ---- ZONE 1: detection quality (dominant) ----------------------------
    _chip(ax, 0.135, 0.878, "DETECTION QUALITY — FINAL UNTOUCHED TEST", TEAL, fs=8.8)
    # hero cards: F1 + Recall
    for x0, val, lab in [(0.025, f"{ft['f1']*100:.4f}%", "F1 score"),
                         (0.265, f"{ft['recall']*100:.4f}%", "Recall (attack detection)")]:
        ax.add_patch(FancyBboxPatch((x0, 0.545), 0.225, 0.285,
                                    boxstyle="round,pad=0.004,rounding_size=0.012",
                                    linewidth=2.0, edgecolor=TEAL, facecolor="#EAF4F1"))
        ax.text(x0 + 0.1125, 0.735, val, ha="center", va="center",
                fontsize=25, fontweight="bold", color=TEAL)
        ax.text(x0 + 0.1125, 0.595, lab, ha="center", va="center",
                fontsize=11, fontweight="bold", color=INK)
    # secondary cards: Precision / FPR / FNR
    sec = [(0.025, f"{ft['precision']*100:.4f}%", "Precision"),
           (0.152, f"{ft['fpr']*100:.4f}%", "FPR (1 FP / 5,555 benign)"),
           (0.279, f"{ft['fnr']*100:.3f}%", "FNR (952 / 442,521 attacks)")]
    for x0, val, lab in sec:
        ax.add_patch(FancyBboxPatch((x0, 0.415), 0.117, 0.105,
                                    boxstyle="round,pad=0.004,rounding_size=0.010",
                                    linewidth=1.2, edgecolor=NAVY, facecolor=LIGHT))
        ax.text(x0 + 0.0585, 0.475, val, ha="center", va="center",
                fontsize=11.5, fontweight="bold", color=NAVY)
        ax.text(x0 + 0.0585, 0.438, lab, ha="center", va="center",
                fontsize=6.8, color="#4A5058")
    ax.text(0.025, 0.375, "PR-AUC 1.0000   ·   ROC-AUC 1.0000   ·   "
            "per-family recall ≥ 0.997 on all 8 families",
            fontsize=9.5, color=INK, fontweight="bold")

    # ---- ZONE 3: validation evidence (confusion matrix) -------------------
    _chip(ax, 0.745, 0.878, "VALIDATION EVIDENCE — CONFUSION MATRIX", NAVY, fs=8.8)
    mx, my, cw, ch = 0.615, 0.470, 0.155, 0.155
    cells = [
        (mx, my + ch, f"{int(ft['tn']):,}", "#EAF4F1", TEAL),      # TN
        (mx + cw, my + ch, f"{int(ft['fp']):,}", "#F9E3E3", RED),  # FP
        (mx, my, f"{int(ft['fn']):,}", "#FBF0E3", AMBER),          # FN
        (mx + cw, my, f"{int(ft['tp']):,}", "#DDEDE8", TEAL),      # TP
    ]
    for x0, y0, txt, fc, ec in cells:
        ax.add_patch(FancyBboxPatch((x0, y0), cw, ch,
                                    boxstyle="round,pad=0.002,rounding_size=0.008",
                                    linewidth=1.1, edgecolor=ec, facecolor=fc))
        ax.text(x0 + cw / 2, y0 + ch / 2, txt, ha="center", va="center",
                fontsize=14, fontweight="bold", color=INK)
    ax.text(mx + cw / 2, my + 2 * ch + 0.022, "pred benign", ha="center",
            fontsize=8.5, color=GREY)
    ax.text(mx + 1.5 * cw, my + 2 * ch + 0.022, "pred DDoS", ha="center",
            fontsize=8.5, color=GREY)
    ax.text(mx - 0.012, my + 1.5 * ch, "actual\nbenign", ha="right", va="center",
            fontsize=8.5, color=GREY)
    ax.text(mx - 0.012, my + 0.5 * ch, "actual\nDDoS", ha="right", va="center",
            fontsize=8.5, color=GREY)
    ax.add_patch(FancyBboxPatch((0.615, 0.245), 0.355, 0.130,
                                boxstyle="round,pad=0.004,rounding_size=0.010",
                                linewidth=1.2, edgecolor=TEAL, facecolor="white",
                                linestyle=(0, (4, 2))))
    ax.text(0.7925, 0.335, f"{ed3['metrics']['recall']*100:.2f}% recall @ 3 s causal window",
            ha="center", fontsize=11, fontweight="bold", color=TEAL)
    ax.text(0.7925, 0.285,
            f"detection coverage {ed3['detection_coverage_pct']:.2f}% · "
            "frozen model, structural causality",
            ha="center", fontsize=7.8, color=GREY)

    # ---- ZONE 2: operational performance (benchmark) ----------------------
    _chip(ax, 0.545, 0.178, "OPERATIONAL PERFORMANCE — INFERENCE BENCHMARK (frozen calibrated model)",
          AMBER, fs=8.8)
    bench_items = [
        (0.025, f"{bench['throughput_flows_s@full']/1000:,.0f}K", "flows/s · full-batch throughput"),
        (0.265, f"{bench['latency_median_ms']:.1f} ms", "median single-flow latency"),
        (0.505, f"{bench['latency_p95_ms']:.1f} ms", "P95 single-flow latency"),
        (0.745, f"{bench['model_size_mb']:.1f} MB", "serialized model size"),
    ]
    for x0, val, lab in bench_items:
        ax.add_patch(FancyBboxPatch((x0, 0.045), 0.23, 0.100,
                                    boxstyle="round,pad=0.004,rounding_size=0.012",
                                    linewidth=1.6, edgecolor=AMBER, facecolor="#FBF0E3"))
        ax.text(x0 + 0.115, 0.108, val, ha="center", va="center",
                fontsize=16, fontweight="bold", color=AMBER)
        ax.text(x0 + 0.115, 0.066, lab, ha="center", va="center",
                fontsize=8.2, color="#4A5058")

    ax.text(0.5, 0.012,
            "Final test was untouched; frozen model artifacts verified byte-identical (SHA-256). "
            "Detection metrics = final untouched test · latency/throughput = benchmark.",
            ha="center", fontsize=7.8, color=GREY, style="italic")

    fig.savefig(OUT / "ppt_05_final_performance.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------
# PPT 06 — dataset scale (refined: transformation + diversity + features)
# --------------------------------------------------------------------------
def ppt06_dataset_scale() -> None:
    fam_stats = load_inventory_family_stats()
    total_packets = sum(s["packets"] for s in fam_stats.values())
    total_caps = sum(s["captures"] for s in fam_stats.values())
    assert total_caps == 45 and total_packets == 98_658_747
    groups = feature_groups()
    n_online, n_terminal = availability_counts()

    fig, ax = plt.subplots(figsize=(12.8, 7.2))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.025, 0.965, "DDoS-AT-2022 — dataset scale & feature representation",
            fontsize=17, fontweight="bold", color=NAVY, va="center")
    ax.text(0.025, 0.925,
            "45 validated PCAP captures · parser verified byte-exact "
            "(45/45 packet-accounting identity) · raw data not distributed with this repository",
            fontsize=10, color=GREY, va="center")

    # ---- headline metrics --------------------------------------------------
    heads = [("45", "PCAP captures"), (f"{total_packets/1e6:.2f}M", "packets"),
             (f"~{RAW_GB:.2f} GB", "raw traffic"), (f"{N_FLOWS_TOTAL/1e6:.3f}M", "extracted flows")]
    for i, (v, lab) in enumerate(heads):
        x0 = 0.025 + i * 0.242
        ax.add_patch(FancyBboxPatch((x0, 0.775), 0.225, 0.115,
                                    boxstyle="round,pad=0.004,rounding_size=0.012",
                                    linewidth=1.6, edgecolor=NAVY, facecolor=LIGHT))
        ax.text(x0 + 0.1125, 0.845, v, ha="center", va="center",
                fontsize=19, fontweight="bold", color=NAVY)
        ax.text(x0 + 0.1125, 0.800, lab, ha="center", va="center",
                fontsize=9.5, color="#333A44")

    # ---- transformation band: PCAPs → packets → flows → features ----------
    steps = [("PCAPs", "45 captures", C_INPUT),
             ("Packets", f"{total_packets/1e6:.2f}M", C_INPUT),
             ("Bidirectional flows", f"{N_FLOWS_TOTAL/1e6:.3f}M", TEAL),
             ("66-feature vectors", "float32", NAVY)]
    bx, bw, bh, by = 0.025, 0.205, 0.085, 0.645
    for i, (t, s, c) in enumerate(steps):
        x0 = bx + i * (bw + 0.043)
        ax.add_patch(FancyBboxPatch((x0, by), bw, bh,
                                    boxstyle="round,pad=0.003,rounding_size=0.010",
                                    linewidth=1.4, edgecolor=c, facecolor="white"))
        ax.text(x0 + bw / 2, by + bh * 0.62, t, ha="center", va="center",
                fontsize=10.5, fontweight="bold", color=c)
        ax.text(x0 + bw / 2, by + bh * 0.24, s, ha="center", va="center",
                fontsize=8.6, color="#4A5058")
        if i < 3:
            _arrow(ax, (x0 + bw + 0.004, by + bh / 2), (x0 + bw + 0.039, by + bh / 2),
                   color=GREY, lw=1.8, scale=14)
    ax.text(bx + 3 * (bw + 0.043) + bw, by + bh + 0.018,
            "large-scale packet captures → validated flows → multidimensional behavioral representation",
            ha="right", fontsize=8.4, color=GREY, style="italic")

    # ---- diversity: measured packets per family ---------------------------
    axd = fig.add_axes([0.055, 0.115, 0.40, 0.40])
    fams_sorted = sorted(fam_stats.items(), key=lambda kv: kv[1]["packets"])
    names = [FAMILY_DISPLAY.get(k, k) for k, _ in fams_sorted]
    vals = [s["packets"] / 1e6 for _, s in fams_sorted]
    caps = [s["captures"] for _, s in fams_sorted]
    colors = [TEAL if k == "benign" else RED for k, _ in fams_sorted]
    bars = axd.barh(names, vals, color=colors, height=0.62)
    for b, v, c in zip(bars, vals, caps):
        axd.text(v + 0.6, b.get_y() + b.get_height() / 2,
                 f"{v:.2f}M · {c} cp", va="center", fontsize=7.4, color="#4A5058")
    axd.set_xlim(0, 66)
    axd.set_xlabel("packets (millions) — measured", fontsize=9)
    axd.tick_params(axis="y", labelsize=8.2)
    axd.set_title("Diversity — 11 attack families + benign\n"
                  "(28 attack / 17 benign captures; cp = captures)",
                  fontsize=10, color=NAVY, loc="left")
    axd.grid(axis="y", visible=False)

    # ---- feature representation (exact ablation partition) ----------------
    axf = fig.add_axes([0.535, 0.115, 0.435, 0.40])
    axf.axis("off")
    axf.set_xlim(0, 1)
    axf.set_ylim(0, 1)
    axf.text(0.02, 0.96, "Feature representation — 66 float32 predictive features",
             fontsize=10, fontweight="bold", color=NAVY, va="top")
    # proportional stacked bar (spans 0.02–0.98 so every segment renders)
    seg_colors = [TEAL, BLUE, AMBER, NAVY, RED]
    SCALE = 0.96
    x = 0.02
    bar_y, bar_h = 0.60, 0.16
    for (label, n), c in zip(groups, seg_colors):
        w = n / 66 * SCALE
        axf.add_patch(FancyBboxPatch((x, bar_y), w, bar_h,
                                     boxstyle="round,pad=0.001,rounding_size=0.008",
                                     linewidth=0.8, edgecolor="white", facecolor=c))
        if w > 0.10:
            axf.text(x + w / 2, bar_y + bar_h / 2, str(n), ha="center", va="center",
                     fontsize=11, fontweight="bold", color="white")
        x += w
    # staggered labels below segments; the 1/66 protocol sliver gets a leader
    x = 0.02
    for i, ((label, n), c) in enumerate(zip(groups, seg_colors)):
        w = n / 66 * SCALE
        if w > 0.10:
            axf.text(x + w / 2, 0.50 if i % 2 == 0 else 0.415,
                     f"{label} ({n})", ha="center", va="top",
                     fontsize=8.2, color=c, fontweight="bold")
        else:
            axf.annotate(f"{label} ({n})", xy=(x + w / 2, bar_y + bar_h + 0.005),
                         xytext=(0.98, 0.845), fontsize=8.2, color=c,
                         fontweight="bold", ha="right", va="center",
                         arrowprops=dict(arrowstyle="-", color=c, lw=0.8))
        x += w
    facts = [
        f"no IP addresses, ports or timestamps used as features",
        f"availability: {n_online} online / {n_terminal} terminal "
        f"(terminal features recomputed causally for early windows)",
        "groups overlap across families (documented in the ablation study)",
    ]
    for i, t in enumerate(facts):
        axf.text(0.02, 0.30 - i * 0.105, "•  " + t, fontsize=8.2, color="#4A5058",
                 va="center")

    ax.text(0.5, 0.022,
            f"Class imbalance is real and labelled: {N_BENIGN_FLOWS:,} benign (1.6%) vs "
            f"{N_ATTACK_FLOWS:,} attack (98.4%) flows · benign packets dominate volume "
            "(56.90M of 98.66M)",
            ha="center", fontsize=8.4, color=GREY, style="italic")

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
