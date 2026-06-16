#!/usr/bin/env python3
"""Render benchmark charts (PNG) from the CSV files produced by the benchmarks.

The benchmarks repeat each measurement many times; the CSV carries
min / mean / max (and stddev), so the charts show error bars / bands.

Usage:
    ./build-release/cankeydist_bench_ops       --csv > docs/data/operations.csv
    ./build-release/cankeydist_bench_scenarios --csv > docs/data/scenarios.csv
    python3 scripts/plot_benchmarks.py

Outputs: docs/images/operations.png, tcomp.png, scaling.png
"""

import csv
import pathlib

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "data"
IMG = ROOT / "docs" / "images"
IMG.mkdir(parents=True, exist_ok=True)

GREEN = "#1D9E75"
CORAL = "#D85A30"
BLUE = "#185FA5"


def read_operations():
    ops, tcomp = {}, {}
    with open(DATA / "operations.csv") as f:
        for row in csv.DictReader(f):
            rec = {k: float(row[k]) for k in ("min_us", "mean_us", "max_us", "stddev_us")}
            (tcomp if row["operation"].startswith("Tcomp") else ops)[row["operation"]] = rec
    return ops, tcomp


def read_scenarios():
    out = {"n": [], "best": ([], [], []), "worst": ([], [], [])}
    with open(DATA / "scenarios.csv") as f:
        for row in csv.DictReader(f):
            out["n"].append(int(row["N"]))
            for who in ("best", "worst"):
                for j, k in enumerate(("min", "mean", "max")):
                    out[who][j].append(float(row[f"{who}_{k}"]))
    return out


def plot_operations(ops):
    fig, ax = plt.subplots(figsize=(7, 3.6))
    names = list(ops.keys())
    means = [ops[k]["mean_us"] for k in names]
    lo = [ops[k]["mean_us"] - ops[k]["min_us"] for k in names]
    hi = [ops[k]["max_us"] - ops[k]["mean_us"] for k in names]
    bars = ax.barh(names, means, xerr=[lo, hi], color=BLUE, height=0.6,
                   error_kw=dict(ecolor="#333", capsize=4, lw=1))
    ax.invert_yaxis()
    ax.set_xlabel("Time per operation (microseconds)")
    ax.set_title("Per-operation cost (mean, error bars = min/max over 20 runs)")
    ax.set_xlim(0, max(ops[k]["max_us"] for k in names) * 1.22)
    for b, k in zip(bars, names):
        ax.text(ops[k]["max_us"] + ax.get_xlim()[1] * 0.015, b.get_y() + b.get_height() / 2,
                "{:.2f}".format(ops[k]["mean_us"]), va="center", fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(IMG / "operations.png", dpi=150)
    plt.close(fig)


def plot_tcomp(tcomp):
    fig, ax = plt.subplots(figsize=(5.5, 3.4))
    names = list(tcomp.keys())
    means = [tcomp[k]["mean_us"] for k in names]
    err = [tcomp[k]["stddev_us"] for k in names]
    bars = ax.bar(names, means, yerr=err, color=[GREEN, CORAL], width=0.5,
                  error_kw=dict(ecolor="#333", capsize=5, lw=1))
    ax.set_ylabel("Tcomp (microseconds)")
    ax.set_title("ECU computation time: KBKDF vs HKDF (mean +/- stddev)")
    ax.set_ylim(0, max(means) * 1.25)
    for b, m in zip(bars, means):
        ax.text(b.get_x() + b.get_width() / 2, m + max(means) * 0.04,
                "{:.2f}".format(m), ha="center", fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(IMG / "tcomp.png", dpi=150)
    plt.close(fig)


def plot_scaling(s):
    n = s["n"]
    fig, ax = plt.subplots(figsize=(7, 4))
    for who, color, marker, dash, label in (
        ("best", GREEN, "o", "-", "Best case (1 KBKDF + N verify)"),
        ("worst", CORAL, "s", "--", "Worst case (1 KBKDF + 4N verify)"),
    ):
        lo, mean, hi = s[who]
        ax.plot(n, mean, dash, marker=marker, color=color, label=label)
        ax.fill_between(n, lo, hi, color=color, alpha=0.15)
    ax.set_xlabel("Number of ECUs (N)")
    ax.set_ylabel("Master crypto time (microseconds)")
    ax.set_title("Key distribution cost scales linearly with N (band = min/max)")
    ax.grid(True, alpha=0.25)
    ax.legend()
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(IMG / "scaling.png", dpi=150)
    plt.close(fig)


def main():
    ops, tcomp = read_operations()
    plot_operations(ops)
    plot_tcomp(tcomp)
    plot_scaling(read_scenarios())
    print("Wrote operations.png, tcomp.png, scaling.png to", IMG)


if __name__ == "__main__":
    main()
