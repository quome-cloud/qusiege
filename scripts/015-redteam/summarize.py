#!/usr/bin/env python3
# Copyright 2026 Quome. Licensed under the Apache License, Version 2.0.
"""Summarize HAARF-RedTeam results (paper 015) into figures + numbers.tex.

Reads results/015-redteam/*.json (produced by the `redteamrun` bench binary) and
writes figures to papers/015-redteam/figs/ and headline macros to
papers/015-redteam/numbers.tex. Skips any experiment whose results file is absent.
"""
import argparse
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Quome-ish palette.
NAVY, TEAL, AMBER, RED, GREY = "#1b2a4a", "#2a9d8f", "#e9c46a", "#c1432f", "#9aa0a6"
plt.rcParams.update({"font.size": 11, "axes.spines.top": False, "axes.spines.right": False})

macros = {}


def load(results_dir, name):
    p = os.path.join(results_dir, name)
    if not os.path.exists(p):
        print(f"  (skip, absent) {p}")
        return None
    with open(p) as f:
        return json.load(f)


def pct(x):
    """LaTeX-escaped percent for numbers.tex macros."""
    return f"{100 * x:.1f}\\%"


def pctplain(x):
    """Plain percent for matplotlib figure titles (no LaTeX escaping)."""
    return f"{100 * x:.1f}%"


def fig1_discovery(d, figs):
    rounds = [p["round"] for p in d["curve"]]
    cum = [p["cumulative_vulns"] for p in d["curve"]]
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ax.plot(rounds, cum, "-o", color=NAVY, label="continuous (loop-until-dry)")
    ax.axhline(d["one_shot_vulns"], color=RED, ls="--", label=f"one-shot ({d['one_shot_vulns']})")
    ax.set_xlabel("red-team round")
    ax.set_ylabel("distinct vulnerabilities")
    ax.set_title("E1 — continuous vs one-shot discovery")
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(figs, "fig1_discovery.png"), dpi=150)
    plt.close(fig)
    macros["EoneOneShot"] = str(d["one_shot_vulns"])
    macros["EoneContinuous"] = str(d["continuous_vulns"])
    macros["EoneExtra"] = str(d["extra"])
    macros["EoneRoundsToDry"] = str(d["rounds_to_dry"])
    macros["EoneNAttacks"] = str(d["n_attacks"])
    macros["EoneLayersBuilt"] = str(d["coverage"]["layers_built"])
    macros["EoneLayersTotal"] = str(d["coverage"]["layers_total"])


def fig2_regression(d, figs):
    labels = [r["change"].replace("disable-", "") for r in d["per_change"]]
    reopened = [r["reopened"] for r in d["per_change"]]
    fig, ax = plt.subplots(figsize=(5.6, 3.2))
    ax.bar(range(len(labels)), reopened, color=TEAL)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=60, ha="right", fontsize=7)
    ax.set_ylabel("reopened vulns (all caught)")
    ax.set_title(f"E2 — regression gate: {pctplain(d['catch_rate'])} catch")
    fig.tight_layout()
    fig.savefig(os.path.join(figs, "fig2_regression.png"), dpi=150)
    plt.close(fig)
    macros["EtwoCatch"] = pct(d["catch_rate"])
    macros["EtwoReopened"] = str(d["total_reopened"])
    macros["EtwoChanges"] = str(d["n_changes"])
    macros["EtwoClosed"] = str(d["closed_set"])


def fig3_incident(d, figs):
    arms = ["manual", "automated"]
    mttc = [d["manual"]["mttc"], d["automated"]["mttc"]]
    mttr = [d["manual"]["mttr"], d["automated"]["mttr"]]
    x = range(len(arms))
    fig, ax = plt.subplots(figsize=(5.0, 3.2))
    w = 0.35
    ax.bar([i - w / 2 for i in x], mttc, w, label="MTTC", color=NAVY)
    ax.bar([i + w / 2 for i in x], mttr, w, label="MTTR", color=AMBER)
    ax.set_xticks(list(x))
    ax.set_xticklabels(arms)
    ax.set_ylabel("stream time-steps")
    ax.set_title(f"E3 — incident response: {pctplain(d['mttc_reduction_pct'] / 100)} MTTC cut")
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(figs, "fig3_incident.png"), dpi=150)
    plt.close(fig)
    macros["EthreeMttcRed"] = f"{d['mttc_reduction_pct']:.1f}\\%"
    macros["EthreeAutoMttc"] = f"{d['automated']['mttc']:.0f}"
    macros["EthreeManMttc"] = f"{d['manual']['mttc']:.0f}"
    macros["EthreeMttd"] = f"{d['mean_mttd']:.1f}"
    macros["EthreeRecall"] = pct(d["detection_recall"])


def fig4_resilience(d, figs):
    prod = d["production"]
    val = d["validation"]
    fig, ax = plt.subplots(figsize=(5.0, 3.2))
    cats = ["production\ninvariants held", "validation\nbreaks caught"]
    held = [prod["invariants_held"], val["violations_caught"]]
    total = [prod["total"], val["total"]]
    ax.bar(range(2), total, color=GREY, label="total")
    ax.bar(range(2), held, color=TEAL, label="held / caught")
    ax.set_xticks(range(2))
    ax.set_xticklabels(cats, fontsize=9)
    ax.set_ylabel("scenarios")
    ax.set_title("E4 — resilience under injected faults")
    ax.legend(frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(os.path.join(figs, "fig4_resilience.png"), dpi=150)
    plt.close(fig)
    macros["EfourProdHeld"] = str(prod["invariants_held"])
    macros["EfourProdTotal"] = str(prod["total"])
    macros["EfourValCaught"] = str(val["violations_caught"])
    macros["EfourValTotal"] = str(val["total"])


def fig5_cost(d, figs):
    rounds = [p["rounds"] for p in d["curve"]]
    probes = [p["probes"] for p in d["curve"]]
    vulns = [p["vulns"] for p in d["curve"]]
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ax.plot(probes, vulns, "-o", color=NAVY)
    ax.set_xlabel("cumulative probes (cost)")
    ax.set_ylabel("distinct vulnerabilities (coverage)")
    ax.set_title("E5 — cost vs coverage (thoroughness dial)")
    fig.tight_layout()
    fig.savefig(os.path.join(figs, "fig5_cost.png"), dpi=150)
    plt.close(fig)
    macros["EfiveAtlas"] = str(d["atlas_techniques"])
    macros["EfiveNotTested"] = ", ".join(d["not_tested_layers"])
    macros["EfiveBuilt"] = str(d["layers_built"])
    macros["EfiveTotal"] = str(d["layers_total"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results/015-redteam")
    ap.add_argument("--paper", default="papers/015-redteam")
    args = ap.parse_args()
    figs = os.path.join(args.paper, "figs")
    os.makedirs(figs, exist_ok=True)

    jobs = [
        ("e1_discovery.json", fig1_discovery),
        ("e2_regression.json", fig2_regression),
        ("e3_incident.json", fig3_incident),
        ("e4_resilience.json", fig4_resilience),
        ("e5_cost.json", fig5_cost),
    ]
    for name, fn in jobs:
        d = load(args.results, name)
        if d is not None:
            fn(d, figs)
            print(f"  {name} -> figure ok")

    numbers = os.path.join(args.paper, "numbers.tex")
    with open(numbers, "w") as f:
        f.write("% Auto-generated by scripts/015-redteam/summarize.py — do not edit.\n")
        for k, v in macros.items():
            f.write(f"\\renewcommand{{\\{k}}}{{{v}}}\n")
    print(f"wrote {numbers} ({len(macros)} macros)")


if __name__ == "__main__":
    main()
