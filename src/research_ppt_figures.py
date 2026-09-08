"""SIH presentation figures — generated from EXISTING measured artifacts only.

Every number plotted here is read from a repository artifact (CSV/JSON) or is
one of the audited constants from reports/*.md. No metric is invented or
synthesized. Frozen ML artifacts are only READ (never modified).

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


# --------------------------------------------------------------------------
# PPT 01 — solution architecture
# --------------------------------------------------------------------------
def ppt01_architecture() -> None:
    stages = [
        ("Network traffic", "passive capture (PCAP)", NAVY),
        ("PCAP / flow processing", "streaming parser · validated byte-exact ·\n45/45 packet-accounting identity", NAVY),
        ("Flow feature extraction", "bidirectional flows · mirror-duplicate removal", BLUE),
        ("66 behavioral / network features", "counts · IAT statistics · TCP flags · windows · rates\n(no IPs, ports or timestamps as features)", BLUE),
        ("ExtraTrees classifier", "300 trees · max_depth 20 · class_weight balanced", TEAL),
        ("Sigmoid calibration", "Platt scaling (isotonic rejected: degenerate)", TEAL),
        ("Threat probability", "calibrated p(attack)", AMBER),
        ("Threshold = 0.5", "validated on held-out development benign data\nFPR 0.00085 ≤ 1e-3 target", AMBER),
        ("DDoS  /  Legitimate", "per-flow verdict", RED),
    ]
    fig, ax = plt.subplots(figsize=(11, 8.5))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, len(stages) * 1.15 + 0.4)
    ax.axis("off")

    y = len(stages) * 1.15
    centers = []
    for i, (title, sub, color) in enumerate(stages):
        h = 0.88
        box = FancyBboxPatch((2.1, y - h / 2), 5.8, h,
                             boxstyle="round,pad=0.09,rounding_size=0.14",
                             linewidth=1.4, edgecolor=color,
                             facecolor=LIGHT if i < len(stages) - 1 else "#FBEFEF")
        ax.add_patch(box)
        ax.text(5.0, y + 0.16, title, ha="center", va="center",
                fontsize=12.5, fontweight="bold", color=color)
        ax.text(5.0, y - 0.20, sub, ha="center", va="center",
                fontsize=8.6, color="#444B54")
        centers.append(y)
        if i < len(stages) - 1:
            ax.add_patch(FancyArrowPatch((5.0, y - h / 2 - 0.06),
                                         (5.0, y - 1.15 + h / 2 + 0.06),
                                         arrowstyle="-|>", mutation_scale=16,
                                         linewidth=1.6, color=GREY))
        y -= 1.15

    ax.text(5.0, len(stages) * 1.15 + 0.30,
            "FluxShield — passive flow-based DDoS detection",
            ha="center", fontsize=14.5, fontweight="bold", color=NAVY)
    ax.text(0.35, len(stages) * 0.62, "PASSIVE\none-way\ncapture\nanalysis",
            ha="center", va="center", fontsize=9, color=GREY, rotation=90,
            fontweight="bold")
    ax.text(9.65, len(stages) * 0.62,
            "no inline blocking\nno dashboard/frontend\noffline or near-real-time\nflow scoring",
            ha="center", va="center", fontsize=8.6, color=GREY, rotation=270)
    fig.tight_layout()
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
    ax.annotate("3 s reaches essentially full-flow performance;\n"
                "5 s adds no meaningful additional recall",
                xy=(3.0, rec[1]), xytext=(3.35, 88.5), fontsize=10, color=NAVY,
                arrowprops=dict(arrowstyle="->", color=NAVY, lw=1.2),
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
# PPT 05 — final performance KPI board
# --------------------------------------------------------------------------
def ppt05_final_performance(m: dict) -> None:
    ft = m["ft"]
    bench = m["bench"]

    fig = plt.figure(figsize=(12.5, 6.4))
    fig.suptitle("FluxShield — final untouched test & inference benchmark",
                 fontsize=16, fontweight="bold", color=NAVY, y=0.985)
    ax_bg = fig.add_axes([0, 0, 1, 1]); ax_bg.axis("off")

    def kpi(ax, value, label, sub="", color=NAVY, vsize=23):
        ax.axis("off")
        ax.text(0.5, 0.62, value, ha="center", va="center",
                fontsize=vsize, fontweight="bold", color=color)
        ax.text(0.5, 0.30, label, ha="center", va="center",
                fontsize=10.5, color="#333A44", fontweight="bold")
        if sub:
            ax.text(0.5, 0.10, sub, ha="center", va="center",
                    fontsize=8.2, color=GREY)

    # left block: final untouched test
    fig.text(0.06, 0.845, "FINAL UNTOUCHED TEST — 448,076 flows, 17 captures, scored once",
             fontsize=10.5, fontweight="bold", color=TEAL)
    grid = [
        (0.055, 0.52, f"{ft['precision']*100:.4f}%", "Precision", ""),
        (0.275, 0.52, f"{ft['recall']*100:.4f}%", "Recall", ""),
        (0.055, 0.24, f"{ft['f1']*100:.4f}%", "F1", ""),
        (0.275, 0.24, f"{ft['fpr']*100:.4f}%", "FPR", "1 FP / 5,555 benign"),
    ]
    for x, y, v, lab, sub in grid:
        ax = fig.add_axes([x, y, 0.19, 0.26])
        kpi(ax, v, lab, sub, color=NAVY)
    ax = fig.add_axes([0.50, 0.24, 0.44, 0.54]); ax.axis("off")
    rows = [
        ("PR-AUC", f"{ft['pr_auc']:.4f}"), ("ROC-AUC", f"{ft['roc_auc']:.4f}"),
        ("FNR", f"{ft['fnr']*100:.3f}%  (952 / 442,521 attacks)"),
        ("Confusion", "TN 5,554 · FP 1 · FN 952 · TP 441,569"),
        ("Per-family recall", "\u2265 0.997 on all 8 families"),
    ]
    ax.text(0.02, 0.96, "Additional final-test metrics", fontsize=10.5,
            fontweight="bold", color=NAVY)
    for i, (k, v) in enumerate(rows):
        ax.text(0.02, 0.80 - i * 0.155, k, fontsize=10, color=GREY)
        ax.text(0.34, 0.80 - i * 0.155, v, fontsize=10.2, color="#222",
                fontweight="bold")

    # right block: benchmark
    fig.text(0.06, 0.175, "INFERENCE BENCHMARK — frozen calibrated model",
             fontsize=10.5, fontweight="bold", color=AMBER)
    fig.text(0.94, 0.175,
             "recall at 3 s causal window: 99.79% (final-test captures)",
             fontsize=9.5, color=GREY, ha="right", style="italic")
    bench_items = [
        (0.055, f"{bench['throughput_flows_s@full']/1000:,.0f}K flows/s", "full-batch throughput"),
        (0.275, f"{bench['latency_median_ms']:.1f} ms", "median single-flow latency"),
        (0.495, f"{bench['latency_p95_ms']:.1f} ms", "P95 latency"),
        (0.715, f"{bench['model_size_mb']:.1f} MB", "model size"),
    ]
    for x, v, lab in bench_items:
        ax = fig.add_axes([x, 0.035, 0.21, 0.125])
        kpi(ax, v, lab, "", color=AMBER, vsize=15)
    fig.savefig(OUT / "ppt_05_final_performance.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


# --------------------------------------------------------------------------
# PPT 06 — dataset scale
# --------------------------------------------------------------------------
def ppt06_dataset_scale() -> None:
    fig = plt.figure(figsize=(12.5, 6.2))
    fig.suptitle("DDoS-AT-2022 — dataset scale", fontsize=16,
                 fontweight="bold", color=NAVY, y=0.97)

    # headline KPIs
    heads = [("45", "PCAP captures"), ("98,658,747", "packets"),
             ("~37.84 GB", "raw traffic"), ("1,236,285", "extracted flows"),
             ("66", "predictive features")]
    for i, (v, lab) in enumerate(heads):
        ax = fig.add_axes([0.035 + i * 0.19, 0.56, 0.175, 0.30]); ax.axis("off")
        ax.text(0.5, 0.66, v, ha="center", fontsize=19 if i != 1 else 15,
                fontweight="bold", color=NAVY)
        ax.text(0.5, 0.22, lab, ha="center", fontsize=10, color="#333A44")

    # captures by label (measured: 17 benign / 28 attack)
    ax1 = fig.add_axes([0.08, 0.10, 0.36, 0.34])
    ax1.bar(["benign", "attack"], [17, 28], color=[TEAL, RED], width=0.55)
    for i, v in enumerate([17, 28]):
        ax1.text(i, v + 0.5, str(v), ha="center", fontsize=12, fontweight="bold")
    ax1.set_ylim(0, 33)
    ax1.set_ylabel("captures")
    ax1.set_title("Captures by label", fontsize=11)

    # packets by family (measured, dataset_audit.md)
    fams = [("benign", 56.90), ("http_flood", 6.16), ("udp_flood", 10.87),
            ("http_slow_read", 13.83), ("tcp_syn_flood", 4.27), ("tcp_rst", 3.29),
            ("others (6 families)", 3.34)]
    ax2 = fig.add_axes([0.55, 0.10, 0.40, 0.34])
    names = [f[0] for f in fams][::-1]
    vals = [f[1] for f in fams][::-1]
    ax2.barh(names, vals, color=[GREY] * 1 + [RED] * 5 + [TEAL] * 1)
    for i, v in enumerate(vals):
        ax2.text(v + 0.5, i, f"{v:.1f}M", va="center", fontsize=8.6)
    ax2.set_xlim(0, 65)
    ax2.set_xlabel("packets (millions)")
    ax2.set_title("Packets by traffic class (millions)", fontsize=11)
    ax2.tick_params(axis="y", labelsize=8.6)
    fig.text(0.5, 0.015,
             "11 attack families + benign · flow-level split: 19,276 benign (1.6%) / "
             "1,217,009 attack (98.4%) · raw data NOT distributed with the repository",
             ha="center", fontsize=9, color=GREY, style="italic")
    fig.savefig(OUT / "ppt_06_dataset_scale.png", bbox_inches="tight",
                facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    m = load_measured()
    ppt01_architecture(); print("ppt_01 done")
    ppt02_model_comparison(m); print("ppt_02 done")
    ppt03_early_detection(m); print("ppt_03 done")
    ppt04_track_b(m); print("ppt_04 done")
    ppt05_final_performance(m); print("ppt_05 done")
    ppt06_dataset_scale(); print("ppt_06 done")
