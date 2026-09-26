"""Research-strengthening figures — measured results only, no invented values.

Reads the four analyses' JSON/CSV outputs and renders reports/figures/research/*.png.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

RD = Path("experiments/research")
OUT = Path("reports/figures/research")
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({"figure.dpi": 150, "font.size": 9, "axes.grid": True,
                     "grid.alpha": 0.3, "axes.spines.top": False,
                     "axes.spines.right": False})


def fig1_duplicate_sensitivity() -> None:
    s = json.load(open("reports/duplicate_sensitivity_results.json"))
    s1 = s["S1_frozen_model"]
    s2 = s["S2_frozen_config_retrain_A2"]
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6))

    # S1: frozen model full vs dedup (dev table)
    ax = axes[0]
    metrics = ["recall", "precision", "f1", "fnr"]
    full = [s1["full"][k] for k in metrics]
    ded = [s1["dedup"][k] for k in metrics]
    x = np.arange(len(metrics))
    ax.bar(x - 0.18, full, 0.36, label=f"full dev ({s['original_dev_rows']:,} rows)", color="#4C72B0")
    ax.bar(x + 0.18, ded, 0.36, label=f"dedup ({s['deduplicated_dev_rows']:,} rows)", color="#DD8452")
    ax.set_xticks(x, metrics)
    ax.set_ylim(0.995, 1.0005)
    ax.set_title(f"S1: frozen model, dev table\n(dups removed: {s['duplicate_rows_removed']:,} = {s['duplicate_pct']}%)")
    ax.set_ylabel("metric value")
    for xi, v in zip(x, full):
        y_lab = v + 0.0002 if v > 0.995 else 0.9951  # keep labels inside the axis
        ax.text(xi - 0.18, y_lab, f"{v:.4f}", ha="center", fontsize=6.5)
    ax.legend(fontsize=7, loc="lower right")

    # S2: matched-partition retrain, per-fold recall (FPR counts annotated)
    ax = axes[1]
    ff = pd.read_csv(RD / "dup_sensitivity_S2_full_folds.csv")
    fd = pd.read_csv(RD / "dup_sensitivity_S2_dedup_folds.csv")
    ax.plot(ff["fold"], ff["recall"], "o-", label=f"retrain full (mean R={s2['full']['recall']:.5f})")
    ax.plot(fd["fold"], fd["recall"], "s--", label=f"retrain dedup (mean R={s2['dedup']['recall']:.5f})")
    for _, r in ff.iterrows():
        ax.annotate(f"FP={int(r['fp'])}", (r["fold"], r["recall"]),
                    textcoords="offset points", xytext=(0, -13), fontsize=6.5,
                    ha="center", color="#4C72B0")
    for _, r in fd.iterrows():
        ax.annotate(f"FP={int(r['fp'])}", (r["fold"], r["recall"]),
                    textcoords="offset points", xytext=(0, 7), fontsize=6.5,
                    ha="center", color="#DD8452")
    ax.set_xticks(ff["fold"])
    ax.set_xlabel("A-2 fold (shared capture partition; FP counts annotated)")
    ax.set_ylabel("fold recall")
    ax.set_ylim(0.995, 1.0006)
    ax.set_title("S2: frozen-config retrain per fold\n(same captures both arms)")
    ax.legend(fontsize=7, loc="lower left")
    fig.suptitle("Exact-duplicate sensitivity (development data only)", y=1.02)
    fig.tight_layout()
    fig.savefig(OUT / "duplicate_sensitivity.png", bbox_inches="tight")
    plt.close(fig)


def fig2_feature_ablation() -> None:
    s = json.load(open("reports/feature_ablation_results.json"))
    a = pd.DataFrame(s["results_A2_folds_mean"])
    if "trackB_agg_recall" not in a.columns:  # older runs: merge from trackB block
        b = pd.DataFrame(s["results_trackB"])
        a = a.merge(b[["config", "trackB_agg_recall"]], on="config")
    m = a
    order = ["A_all_66", "B_rate_statistical", "C_directional", "D_timing_iat",
             "E_tcp_behavior", "F_protocol_indicator",
             "cum1_base_rate", "cum2_+directional", "cum3_+timing", "cum4_+tcp"]
    m = m.set_index("config").loc[order].reset_index()

    fig, axes = plt.subplots(1, 2, figsize=(11.5, 4.2), sharey=True)
    y = np.arange(len(m))
    colors = ["#4C72B0"] * 6 + ["#55A868"] * 4

    ax = axes[0]
    ax.barh(y, m["recall"], color=colors)
    ax.set_yticks(y, [f"{c} (k={k})" for c, k in zip(m["config"], m["n_features"])], fontsize=7.5)
    ax.invert_yaxis()
    ax.set_xlim(0.3, 1.01)
    ax.set_xlabel("A-2 mean recall (in-distribution)")
    ax.set_title("In-distribution recall (capture-disjoint folds)")
    for yi, v in zip(y, m["recall"]):
        ax.text(v + 0.005, yi, f"{v:.4f}", va="center", fontsize=6.5)

    ax = axes[1]
    ax.barh(y, m["trackB_agg_recall"], color=colors)
    ax.set_xlim(0.3, 1.01)
    ax.set_xlabel("Track B recall (never-seen families)")
    ax.set_title("Never-seen-family recall (generalization)")
    for yi, v in zip(y, m["trackB_agg_recall"]):
        ax.text(v + 0.005, yi, f"{v:.4f}", va="center", fontsize=6.5)

    fig.suptitle("Feature-group ablation — fixed frozen ExtraTrees config (dev only)", y=1.02)
    fig.tight_layout()
    fig.savefig(OUT / "feature_ablation.png", bbox_inches="tight")
    plt.close(fig)


def fig3_error_analysis() -> None:
    s = json.load(open("reports/error_analysis_results.json"))
    fnf = s["final_test_errors"]["fn_by_family"]
    fams = sorted(fnf, key=lambda k: -fnf[k]["n_fn"])
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.0))

    ax = axes[0]
    n_fn = [fnf[f]["n_fn"] for f in fams]
    rates = [fnf[f]["fn_rate"] * 100 for f in fams]
    x = np.arange(len(fams))
    bars = ax.bar(x, n_fn, color="#C44E52")
    ax.set_xticks(x, [f.replace("_", "\n") for f in fams], fontsize=7)
    ax.set_ylabel("false negatives (of 442,521 attack flows)")
    ax.set_title("Final-test FN count by family (total 952)")
    for xi, (n, r) in enumerate(zip(n_fn, rates)):
        ax.text(xi, n + 8, f"{n}\n({r:.3f}%)", ha="center", fontsize=6.5)
    ax.set_ylim(0, max(n_fn) * 1.25)

    # 1s vs 3s/5s recall per family (early-window failures)
    ed = json.load(open("reports/early_detection_results.json"))
    fam_rec = {}
    for w in ("1.0", "3.0"):
        fam_rec[w] = {r["family"]: r["recall"]
                      for r in ed["results"][w]["family_recall"] if r["family"] != "benign"}
    af = pd.read_csv(RD / "error_1s_family_evidence.csv")  # measured 1s re-extraction
    order = af.sort_values("recall_1s")["family"].tolist()
    r1 = [af.set_index("family").loc[f, "recall_1s"] for f in order]
    r3 = [fam_rec["3.0"][f] for f in order]
    x = np.arange(len(order))
    ax = axes[1]
    ax.bar(x - 0.2, r1, 0.4, label="1 s window", color="#C44E52")
    ax.bar(x + 0.2, r3, 0.4, label="3 s window", color="#4C72B0")
    ax.set_xticks(x, [f.replace("_", "\n") for f in order], fontsize=7)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("recall")
    ax.set_title("Early-window recall: slow-rate families recover by 3 s")
    ax.legend(fontsize=7)

    fig.suptitle("Error analysis — where and why the frozen model misses", y=1.02)
    fig.tight_layout()
    fig.savefig(OUT / "error_analysis.png", bbox_inches="tight")
    plt.close(fig)


def fig4_threshold_sensitivity() -> None:
    s = json.load(open("reports/threshold_sensitivity_results.json"))
    df = pd.DataFrame(s["grid"])
    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    ax.plot(df["threshold"], df["recall"], "o-", color="#4C72B0", label="recall (dev cal split)")
    ax.plot(df["threshold"], df["fpr"], "s-", color="#C44E52", label="FPR (dev cal split)")
    ax.plot(df["threshold"], df["f1"], "^--", color="#55A868", label="F1 (dev cal split)")
    ax.axvline(0.5, color="k", linestyle=":", linewidth=1.2)
    ax.annotate("deployed t=0.5\n(FROZEN)", xy=(0.5, 0.35), fontsize=8,
                ha="left", xytext=(0.52, 0.30))
    ax.axhline(1e-3, color="#C44E52", linestyle=":", linewidth=0.9, alpha=0.7)
    ax.text(0.06, 1.6e-3, "FPR target 1e-3", fontsize=7, color="#C44E52")
    ax.set_yscale("log")
    ax.set_ylim(1e-4, 1.2)
    ax.set_xlabel("decision threshold")
    ax.set_ylabel("metric value (log scale)")
    ax.set_title("Threshold sensitivity — development calibration split only\n"
                 "(threshold.json unchanged; Track B caps the operating point at ~0.5)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(OUT / "threshold_sensitivity.png", bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    fig1_duplicate_sensitivity()
    print("saved", OUT / "duplicate_sensitivity.png")
    fig2_feature_ablation()
    print("saved", OUT / "feature_ablation.png")
    fig3_error_analysis()
    print("saved", OUT / "error_analysis.png")
    fig4_threshold_sensitivity()
    print("saved", OUT / "threshold_sensitivity.png")
