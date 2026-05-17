#!/usr/bin/env python3
"""Generate thesis-ready plots from thesis/results/timings.csv.

Outputs PDF + PNG into thesis/results/plots/:
  g1_proof_primitives.pdf     per-proof prove/verify cost (grouped bars)
  g2_proof_sizes.pdf          proof and ballot byte sizes (horizontal bars)
  g3_batch_amortization.pdf   batch verify, individual vs batched, on log-x
  g4_ballot_vs_n.pdf          ballot create / verify across election N (log-log)
  g4_setproof_vs_n.pdf        commitment-set proof prove/verify across N
  g4_full_pipeline_vs_n.pdf   tally full_pipeline across N
  g5_per_proof_compare.pdf    hand-rolled vs library-backed bar chart
  g6_tally_breakdown.pdf      serial decrypt vs full pipeline across N

Each plot skips silently if its data is absent — partial runs still produce
the plots they have data for.
"""

from __future__ import annotations

import csv
import math
import re
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "thesis" / "results"
PLOTS = RESULTS / "plots"


def load_timings() -> list[dict]:
    path = RESULTS / "timings.csv"
    if not path.exists():
        return []
    out = []
    for row in csv.DictReader(path.open()):
        try:
            row["mean_ns"] = float(row["mean_ns"])
            row["ci_lo_ns"] = float(row["ci_lo_ns"])
            row["ci_hi_ns"] = float(row["ci_hi_ns"])
        except (TypeError, ValueError):
            row["mean_ns"] = float("nan")
            row["ci_lo_ns"] = float("nan")
            row["ci_hi_ns"] = float("nan")
        # Default source to "aws" if older CSV doesn't have the column.
        row.setdefault("source", "aws")
        out.append(row)
    return out


def load_sizes() -> list[dict]:
    path = RESULTS / "sizes.csv"
    if not path.exists():
        return []
    out = []
    for row in csv.DictReader(path.open()):
        try:
            row["bytes"] = int(row["bytes"])
        except (TypeError, ValueError):
            row["bytes"] = 0
        out.append(row)
    return out


def save(fig, name: str) -> None:
    PLOTS.mkdir(parents=True, exist_ok=True)
    pdf = PLOTS / f"{name}.pdf"
    png = PLOTS / f"{name}.png"
    fig.tight_layout()
    fig.savefig(pdf)
    fig.savefig(png, dpi=160)
    plt.close(fig)
    print(f"  wrote {pdf.name} + {png.name}")


# ---------- G1: Proof primitives — headline + scaling charts ----------
def plot_g1(timings: list[dict]) -> None:
    """A grouped bar chart at the *largest measured scale* for each proof type
    (so the chart is honest about what was measured) plus a multi-panel
    scaling figure for the proofs whose cost actually varies with a parameter.
    """
    aws = [r for r in timings if r.get("source", "aws") == "aws"]

    # ---- (a) headline bar: largest scale per proof ----
    headline_scale = {
        "representation": "8",      # n ∈ {1, 2, 4, 8}
        "dleq": "",                  # single value, no parameter
        "enc_validity": "",
        "serial_validity": "",
        "bit_vector": "64",
        "commitment_set": "N=256",  # comparable to other proofs, not the max
    }
    pretty = {
        "representation": "Repr.\n(n=8)",
        "dleq": "DLEQ",
        "enc_validity": "EncVal",
        "serial_validity": "SerVal",
        "bit_vector": "BitVec\n(k'=64)",
        "commitment_set": "Set\n(N=256)",
    }
    prove: dict[str, float] = {}
    verify: dict[str, float] = {}
    for r in aws:
        g = r["group"]
        if g not in headline_scale:
            continue
        if r["function"] not in ("prove", "verify"):
            continue
        if r["value"] != headline_scale[g]:
            continue
        (prove if r["function"] == "prove" else verify)[g] = r["mean_ns"] / 1e3

    keys = [g for g in headline_scale if g in prove or g in verify]
    if keys:
        labels = [pretty[g] for g in keys]
        fig, ax = plt.subplots(figsize=(8, 4.5))
        x = list(range(len(keys)))
        width = 0.4
        ax.bar([i - width / 2 for i in x], [prove.get(g, 0.0) for g in keys], width=width, label="prove", color="#1f77b4")
        ax.bar([i + width / 2 for i in x], [verify.get(g, 0.0) for g in keys], width=width, label="verify", color="#ff7f0e")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_yscale("log")
        ax.set_ylabel("Time (µs, log scale)")
        ax.set_title("Per-proof prover/verifier cost (AWS, headline scale per proof)")
        ax.grid(True, axis="y", which="both", alpha=0.3)
        ax.legend()
        save(fig, "g1_proof_primitives")

    # ---- (b) scaling-line panels: cost vs parameter for the three families
    # that have a meaningful scale parameter (representation n, bit-vector k',
    # commitment-set N).
    def collect(group: str, value_re: str):
        items: dict[int, dict[str, float]] = {}
        for r in aws:
            if r["group"] != group:
                continue
            if r["function"] not in ("prove", "verify"):
                continue
            m = re.search(value_re, r["value"] or "")
            if not m:
                continue
            x = int(m.group(1))
            items.setdefault(x, {})[r["function"]] = r["mean_ns"] / 1e3
        return sorted(items.items())

    families = [
        ("representation", r"^(\d+)$", "Representation",   "n (generators)"),
        ("bit_vector",     r"^(\d+)$", "Bit-vector",       r"$k'$ (slots)"),
        ("commitment_set", r"^N=(\d+)$", "Commitment-set", r"$N$ (voters)"),
    ]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
    drew_any = False
    for ax, (group, vre, title, xlabel) in zip(axes, families):
        rows = collect(group, vre)
        if not rows:
            continue
        xs = [n for n, _ in rows]
        pv = [d.get("prove", float("nan")) for _, d in rows]
        vv = [d.get("verify", float("nan")) for _, d in rows]
        ax.plot(xs, pv, "o-", color="#1f77b4", label="prove")
        ax.plot(xs, vv, "s-", color="#ff7f0e", label="verify")
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_title(title)
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Time (µs)")
        ax.grid(True, which="both", alpha=0.3)
        ax.legend(fontsize=8)
        drew_any = True
    if drew_any:
        fig.suptitle("Scaling of parameterised proof primitives (log-log)")
        save(fig, "g1_proof_primitives_scaling")
    else:
        plt.close(fig)


# ---------- G2: Proof sizes ----------
def plot_g2(sizes: list[dict]) -> None:
    if not sizes:
        return
    # Pick a clean subset: section ∈ {Representation, DLEQ, EncryptionValidity,
    # SerialValidity, BitVector (k=64), CommitmentSet (N=256), Ballot (N=256)}.
    interesting_sections = {
        "REPRESENTATION PROOFS",
        "DLEQ PROOFS",
        "ENCRYPTION-VALIDITY PROOFS",
        "SERIAL-VALIDITY PROOFS",
        "BIT-VECTOR PROOFS",
        "COMMITMENT-SET PROOFS",
        "BALLOT SIZES",
    }
    rows = [r for r in sizes if r["section"] in interesting_sections]
    if not rows:
        rows = sizes  # fall back: plot everything
    # One label per row, sort by size for readability
    rows = sorted(rows, key=lambda r: r["bytes"])
    labels = [f"{r['section'].split()[0].title()}: {r['label']}" if r["section"] else r["label"] for r in rows]
    values = [r["bytes"] for r in rows]
    fig, ax = plt.subplots(figsize=(8, max(4, 0.28 * len(rows) + 1)))
    ax.barh(range(len(rows)), values, color="#2ca02c")
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xscale("log")
    ax.set_xlabel("Size (bytes, log scale)")
    ax.set_title("Proof and ballot sizes")
    ax.grid(True, axis="x", which="both", alpha=0.3)
    save(fig, "g2_proof_sizes")


# ---------- G3: Batch amortization ----------
def plot_g3(timings: list[dict]) -> None:
    groups = ("batch_verify_rep", "batch_verify_dleq", "batch_verify_encval")
    nice = {
        "batch_verify_rep": "Representation",
        "batch_verify_dleq": "DLEQ",
        "batch_verify_encval": "EncryptionValidity",
    }
    fig, ax = plt.subplots(figsize=(7, 4))
    plotted = False
    for g in groups:
        bs_to_ind: dict[int, float] = {}
        bs_to_bat: dict[int, float] = {}
        for r in timings:
            if r["group"] != g or not r["value"]:
                continue
            try:
                bs = int(re.search(r"\d+", r["value"]).group())
            except AttributeError:
                continue
            if r["function"] == "individual":
                bs_to_ind[bs] = r["mean_ns"]
            elif r["function"] == "batch":
                bs_to_bat[bs] = r["mean_ns"]
        common = sorted(set(bs_to_ind) & set(bs_to_bat))
        if not common:
            continue
        speedups = [bs_to_ind[b] / bs_to_bat[b] for b in common]
        ax.plot(common, speedups, "o-", label=nice[g])
        plotted = True
    if not plotted:
        return
    ax.set_xscale("log")
    ax.set_xlabel("Batch size")
    ax.set_ylabel("Speedup (individual / batched)")
    ax.set_title("Batch verification amortization")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    save(fig, "g3_batch_amortization")


# ---------- G4: Election lifecycle vs N ----------
N_RE = re.compile(r"^N(\d+)[/_](.+)$")


def collect_by_n(timings: list[dict], op: str, suffix: str) -> tuple[list[int], list[float], list[float]]:
    """Return parallel arrays (Ns, means, half_widths) for op within group ending in suffix.

    `suffix` matches both `_X` and `/X` separators (Criterion uses `/` in the
    JSON `group_id`, `_` in the on-disk directory name).
    """
    items: dict[int, dict] = {}
    for r in timings:
        m = N_RE.match(r["group"])
        if not m:
            continue
        sep_suffix = suffix.lstrip("_/")
        if not (
            r["group"].endswith(f"/{sep_suffix}")
            or r["group"].endswith(f"_{sep_suffix}")
        ):
            continue
        if r["function"] != op:
            continue
        n = int(m.group(1))
        items[n] = r
    Ns = sorted(items)
    means = [items[n]["mean_ns"] for n in Ns]
    half = [
        max(items[n]["mean_ns"] - items[n]["ci_lo_ns"], items[n]["ci_hi_ns"] - items[n]["mean_ns"])
        for n in Ns
    ]
    return Ns, means, half


def loglog_with_err(ax, Ns, means, half, label):
    if not Ns:
        return False
    x = list(Ns)
    y = [v / 1e6 for v in means]  # ms
    yerr = [v / 1e6 for v in half]
    ax.errorbar(x, y, yerr=yerr, fmt="o-", capsize=3, label=label)
    return True


def plot_g4_ballot(timings: list[dict]) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.5))
    any_data = False
    Ns, means, half = collect_by_n(timings, "create", "_ballot")
    if loglog_with_err(ax, Ns, means, half, "Ballot create"):
        any_data = True
    Ns, means, half = collect_by_n(timings, "verify", "_ballot")
    if loglog_with_err(ax, Ns, means, half, "Ballot verify"):
        any_data = True
    if not any_data:
        return
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("N (voter set size)")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Ballot creation and verification vs N")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    save(fig, "g4_ballot_vs_n")


def plot_g4_setproof(timings: list[dict]) -> None:
    """Use commitment_set scaling group from proof_primitives."""
    items: dict[int, dict[str, dict]] = defaultdict(dict)
    for r in timings:
        if r["group"] != "commitment_set":
            continue
        try:
            n = int(re.search(r"\d+", r["value"]).group())
        except AttributeError:
            continue
        items[n][r["function"]] = r
    Ns = sorted(items)
    if not Ns:
        return
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for op in ("prove", "verify"):
        ys = [items[n][op]["mean_ns"] / 1e6 for n in Ns if op in items[n]]
        xs = [n for n in Ns if op in items[n]]
        if xs:
            ax.plot(xs, ys, "o-", label=op)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Set size N")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Commitment-set proof prove/verify vs N")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    save(fig, "g4_setproof_vs_n")


def plot_g4_full_pipeline(timings: list[dict]) -> None:
    Ns, means, half = collect_by_n(timings, "full_pipeline", "_tally")
    if not Ns:
        return
    fig, ax = plt.subplots(figsize=(7, 4.5))
    loglog_with_err(ax, Ns, means, half, "Tally full pipeline")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("N (voter set size)")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Tally full pipeline vs N")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    save(fig, "g4_full_pipeline_vs_n")


# ---------- G5: hand-rolled vs library-backed ----------
def plot_g5(timings: list[dict]) -> None:
    groups = ("rep_compare", "dleq_compare", "encval_compare", "serval_compare", "bitvec_compare", "set_compare")
    pretty = {
        "rep_compare": "Repr.",
        "dleq_compare": "DLEQ",
        "encval_compare": "EncVal",
        "serval_compare": "SerVal",
        "bitvec_compare": "BitVec",
        "set_compare": "Set",
    }
    pairs: dict[tuple[str, str, str], dict[str, dict]] = defaultdict(dict)
    for r in timings:
        if r["group"] not in groups:
            continue
        if "/" not in r["function"]:
            continue
        op, mode = r["function"].split("/", 1)
        pairs[(r["group"], op, r["value"])][mode] = r

    # We'll plot one bar chart per op (prove, verify) showing handrolled vs lib for each group.
    for op in ("prove", "verify"):
        labels: list[str] = []
        hr_vals: list[float] = []
        lib_vals: list[float] = []
        for (g, this_op, scale), modes in sorted(pairs.items()):
            if this_op != op:
                continue
            if "handrolled" not in modes or "lib" not in modes:
                continue
            label = pretty[g]
            if scale and scale != "—":
                label = f"{label}\n({scale})"
            labels.append(label)
            hr_vals.append(modes["handrolled"]["mean_ns"] / 1e3)  # µs
            lib_vals.append(modes["lib"]["mean_ns"] / 1e3)
        if not labels:
            continue
        fig, ax = plt.subplots(figsize=(max(7, 0.7 * len(labels) + 2), 4.5))
        x = list(range(len(labels)))
        width = 0.4
        ax.bar([i - width / 2 for i in x], hr_vals, width=width, label="hand-rolled", color="#1f77b4")
        ax.bar([i + width / 2 for i in x], lib_vals, width=width, label="library", color="#ff7f0e")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=9)
        ax.set_ylabel(f"{op} time (µs, log scale)")
        ax.set_yscale("log")
        ax.set_title(f"Hand-rolled vs library-backed — {op}")
        ax.grid(True, axis="y", which="both", alpha=0.3)
        ax.legend()
        save(fig, f"g5_per_proof_compare_{op}")


# ---------- DKG vs N (constancy visualisation) ----------
def plot_dkg_vs_n(timings: list[dict]) -> None:
    items: dict[int, dict[str, float]] = {}
    for r in timings:
        if r.get("source", "aws") != "aws":
            continue
        m = N_RE.match(r["group"])
        if not m or not (r["group"].endswith("_dkg") or r["group"].endswith("/dkg")):
            continue
        n = int(m.group(1))
        items.setdefault(n, {})[r["function"]] = (r["mean_ns"], r["ci_lo_ns"], r["ci_hi_ns"])
    if not items:
        return
    Ns = sorted(items)
    fn = "2of3"
    if fn not in items[Ns[0]]:
        # Fall back to whatever single function is present.
        fn = next(iter(items[Ns[0]].keys()))
    means = [items[n][fn][0] / 1e6 for n in Ns]
    half = [
        max(items[n][fn][0] - items[n][fn][1], items[n][fn][2] - items[n][fn][0]) / 1e6
        for n in Ns
    ]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.errorbar(Ns, means, yerr=half, fmt="o-", capsize=3, color="#2ca02c", label=f"DKG ({fn})")
    # Reference line at the mean across all N values.
    avg = sum(means) / len(means)
    ax.axhline(avg, linestyle="--", color="gray", alpha=0.5, label=f"mean = {avg:.3f} ms")
    ax.set_xscale("log")
    ax.set_xlabel("N (voter set size)")
    ax.set_ylabel("DKG time (ms)")
    ax.set_title(r"DKG cost is independent of $N$ (3 authorities, threshold 2)")
    ax.grid(True, which="both", alpha=0.3)
    ax.legend()
    save(fig, "dkg_vs_n")


# ---------- G6: Tally breakdown ----------
def plot_g6(timings: list[dict]) -> None:
    items_serial: dict[int, float] = {}
    items_full: dict[int, float] = {}
    for r in timings:
        if r["source"] != "aws":
            continue
        m = N_RE.match(r["group"])
        if not m:
            continue
        if not (r["group"].endswith("_tally") or r["group"].endswith("/tally")):
            continue
        n = int(m.group(1))
        if r["function"] == "serial_decrypt_per_tallier":
            items_serial[n] = r["mean_ns"] / 1e6  # ms
        elif r["function"] == "full_pipeline":
            items_full[n] = r["mean_ns"] / 1e6
    Ns = sorted(set(items_serial) | set(items_full))
    if not Ns:
        return
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    x = list(range(len(Ns)))
    width = 0.4
    serial_vals = [items_serial.get(n, 0.0) for n in Ns]
    full_vals = [items_full.get(n, 0.0) for n in Ns]
    ax.bar([i - width / 2 for i in x], serial_vals, width=width, label="serial decrypt (per tallier)", color="#1f77b4")
    ax.bar([i + width / 2 for i in x], full_vals, width=width, label="full pipeline", color="#d62728")
    ax.set_xticks(x)
    ax.set_xticklabels([f"{n:,}" for n in Ns])
    ax.set_xlabel("N (voter set size)")
    ax.set_ylabel("Time (ms, log scale)")
    ax.set_yscale("log")
    ax.set_title("Tally pipeline: per-tallier serial decrypt vs full pipeline")
    ax.grid(True, axis="y", which="both", alpha=0.3)
    ax.legend()
    save(fig, "g6_tally_breakdown")


def main() -> int:
    timings = load_timings()
    sizes = load_sizes()
    if not timings:
        print("no timings.csv rows; run extract.py first", file=sys.stderr)
        return 1
    plot_g1(timings)
    plot_g2(sizes)
    plot_g3(timings)
    plot_g4_ballot(timings)
    plot_g4_setproof(timings)
    plot_g4_full_pipeline(timings)
    plot_g5(timings)
    plot_g6(timings)
    plot_dkg_vs_n(timings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
