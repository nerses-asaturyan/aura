#!/usr/bin/env python3
"""Generate thesis-ready LaTeX (booktabs) and Markdown tables from the CSVs
produced by `extract.py`.

Tables emitted under thesis/results/tables/:
    g1_proof_primitives.tex / .md
    g2_proof_sizes.tex      / .md
    g3_batch_amortization.tex / .md
    g4_election_lifecycle.tex / .md
    g5_handrolled_vs_lib.tex  / .md
    g6_tally_breakdown.tex    / .md

Skips a group cleanly if no rows match (so the script works for partial runs).
"""

from __future__ import annotations

import csv
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "thesis" / "results"
TABLES = RESULTS / "tables"


def fmt_time(ns: float) -> str:
    """Format a nanosecond duration with a sensible unit."""
    if not math.isfinite(ns) or ns <= 0:
        return "—"
    units = [(1e9, "s"), (1e6, "ms"), (1e3, "µs"), (1, "ns")]
    for scale, label in units:
        if ns >= scale:
            v = ns / scale
            if v >= 100:
                return f"{v:.1f} {label}"
            if v >= 10:
                return f"{v:.2f} {label}"
            return f"{v:.3f} {label}"
    return f"{ns:.0f} ns"


def fmt_time_pm(mean: float, lo: float, hi: float) -> str:
    base = fmt_time(mean)
    if not math.isfinite(lo) or not math.isfinite(hi) or mean == 0:
        return base
    half = max(mean - lo, hi - mean)
    pct = 100 * half / mean
    return f"{base} ± {pct:.1f}%"


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024 * 1024:
        return f"{b/1024:.2f} KB"
    return f"{b/(1024*1024):.2f} MB"


def load_timings() -> list[dict]:
    path = RESULTS / "timings.csv"
    if not path.exists():
        return []
    out = []
    for row in csv.DictReader(path.open()):
        for k in ("mean_ns", "ci_lo_ns", "ci_hi_ns"):
            try:
                row[k] = float(row[k])
            except (TypeError, ValueError):
                row[k] = float("nan")
        try:
            row["n_samples"] = int(row["n_samples"])
        except (TypeError, ValueError):
            row["n_samples"] = 0
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


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    cols = list(zip(*([headers] + rows)))
    widths = [max(len(c) for c in col) for col in cols]
    fmt_row = lambda r: "| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |"
    sep = "| " + " | ".join("-" * w for w in widths) + " |"
    return "\n".join([fmt_row(headers), sep] + [fmt_row(r) for r in rows]) + "\n"


def latex_table(headers: list[str], rows: list[list[str]], caption: str, label: str, alignment: str = None) -> str:
    if not rows:
        return ""
    align = alignment or ("l" + "r" * (len(headers) - 1))
    head = " & ".join(_latex_escape(h) for h in headers) + r" \\"
    body = "\n".join(" & ".join(_latex_escape(c) for c in r) + r" \\" for r in rows)
    return (
        "\\begin{table}[h]\n"
        f"  \\centering\n"
        f"  \\caption{{{caption}}}\n"
        f"  \\label{{{label}}}\n"
        f"  \\begin{{tabular}}{{{align}}}\n"
        f"    \\toprule\n"
        f"    {head}\n"
        f"    \\midrule\n"
        f"{body}\n"
        f"    \\bottomrule\n"
        f"  \\end{{tabular}}\n"
        f"\\end{{table}}\n"
    )


def _latex_escape(s: str) -> str:
    return (
        s.replace("\\", r"\textbackslash{}")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("#", r"\#")
        .replace("_", r"\_")
        .replace("$", r"\$")
        .replace("{", r"\{")
        .replace("}", r"\}")
        .replace("~", r"\textasciitilde{}")
        .replace("^", r"\textasciicircum{}")
        .replace("µ", r"$\mu$")
        .replace("±", r"$\pm$")
    )


def write_pair(name: str, headers: list[str], rows: list[list[str]], caption: str, label: str) -> None:
    if not rows:
        print(f"  (skipped {name}: no data)")
        return
    md_path = TABLES / f"{name}.md"
    tex_path = TABLES / f"{name}.tex"
    md_path.write_text(md_table(headers, rows))
    tex_path.write_text(latex_table(headers, rows, caption, label))
    print(f"  wrote {md_path.name} + {tex_path.name}  ({len(rows)} rows)")


# ---------- Logical groups ----------

def g1_proof_primitives(timings: list[dict]) -> None:
    """Per-proof prove/verify timings. One row per (proof, op, scale)."""
    interesting = ("representation", "dleq", "enc_validity", "serial_validity", "bit_vector", "commitment_set")
    rows = [r for r in timings if r["group"] in interesting]
    rows = [r for r in rows if r["function"] in ("prove", "verify")]
    out = [
        [r["group"], r["function"], r["value"] or "—", f"{r['n_samples']}", fmt_time_pm(r["mean_ns"], r["ci_lo_ns"], r["ci_hi_ns"])]
        for r in rows
    ]
    out.sort(key=lambda x: (x[0], x[1], x[2]))
    write_pair(
        "g1_proof_primitives",
        ["Proof", "Op", "Scale", "Samples", "Time (mean ± half-CI %)"],
        out,
        "Per-proof prove/verify timings (hand-rolled).",
        "tab:g1_proof_primitives",
    )


def g2_proof_sizes(sizes: list[dict]) -> None:
    rows = [
        [r["section"] or "—", r["label"], r["raw_value"], f"{r['bytes']}"]
        for r in sizes
    ]
    write_pair(
        "g2_proof_sizes",
        ["Section", "Label", "Reported", "Bytes"],
        rows,
        "Proof and ballot sizes from proof\\_sizes.rs.",
        "tab:g2_proof_sizes",
    )


def g3_batch_amortization(timings: list[dict]) -> None:
    groups = ("batch_verify_rep", "batch_verify_dleq", "batch_verify_encval")
    rows: list[list[str]] = []
    # We expect (group, function ∈ {individual, batch}, value = batch size).
    by_key: dict[tuple[str, str], dict[str, dict]] = {}
    for r in timings:
        if r["group"] in groups:
            key = (r["group"], r["value"])
            by_key.setdefault(key, {})[r["function"]] = r
    # Sort by (group, then batch size as integer).
    def sort_key(item):
        (group, scale), _ = item
        try:
            n = int(scale)
        except (TypeError, ValueError):
            n = 0
        return (group, n)
    for (group, scale), funcs in sorted(by_key.items(), key=sort_key):
        ind = funcs.get("individual")
        bat = funcs.get("batch")
        if ind and bat and bat["mean_ns"] > 0:
            speedup = ind["mean_ns"] / bat["mean_ns"]
            rows.append(
                [
                    group,
                    scale,
                    fmt_time(ind["mean_ns"]),
                    fmt_time(bat["mean_ns"]),
                    f"{speedup:.2f}×",
                ]
            )
    write_pair(
        "g3_batch_amortization",
        ["Group", "Batch size", "Individual", "Batched", "Speedup"],
        rows,
        "Batch-verification amortization for the three batchable proof systems "
        "(standalone benches, no election context).",
        "tab:g3_batch_amortization",
    )


def g3b_election_batch_verify(timings: list[dict]) -> None:
    """Election-scale batch verification: full-ballot verify_batch at each N
    across batch sizes. Shows how long it takes to verify K ballots at once
    for a real-sized commitment list of N voters."""
    by_n: dict[int, dict[int, dict[str, float]]] = {}
    for r in timings:
        m = N_FROM_GROUP.match(r["group"])
        if not m:
            continue
        op = m.group(2)
        # We want N{X}/verify_batch (the full-ballot batch verify), not
        # N{X}/verify_batch_encval (the encryption-validity-only batch).
        if op != "verify_batch":
            continue
        n = int(m.group(1))
        try:
            bs = int(r["value"])
        except (TypeError, ValueError):
            continue
        by_n.setdefault(n, {})[bs] = r["mean_ns"]
    if not by_n:
        return
    batch_sizes = sorted({bs for sizes in by_n.values() for bs in sizes})
    headers = ["N"] + [f"batch={bs}" for bs in batch_sizes]
    rows: list[list[str]] = []
    for n in sorted(by_n):
        row = [f"{n:,}"]
        for bs in batch_sizes:
            t = by_n[n].get(bs)
            row.append(fmt_time(t) if t is not None else "—")
        rows.append(row)
    write_pair(
        "g3b_election_batch_verify",
        headers,
        rows,
        "Election-scale full-ballot batch verification: total wall-clock time "
        "to batch-verify the given number of complete ballots for a voter list "
        "of size $N$. Each row is one election scale; each column is one batch "
        "size.",
        "tab:g3b_election_batch_verify",
    )


N_FROM_GROUP = re.compile(r"^N(\d+)[/_](.+)$")


def g4_election_lifecycle(timings: list[dict]) -> None:
    rows = []
    for r in timings:
        m = N_FROM_GROUP.match(r["group"])
        if not m:
            continue
        n = int(m.group(1))
        op = m.group(2)
        rows.append(
            [
                f"{n:,}",
                op,
                r["function"] or "—",
                r["value"] or "—",
                f"{r['n_samples']}",
                fmt_time_pm(r["mean_ns"], r["ci_lo_ns"], r["ci_hi_ns"]),
            ]
        )
    rows.sort(key=lambda x: (int(x[0].replace(",", "")), x[1], x[2], x[3]))
    write_pair(
        "g4_election_lifecycle",
        ["N", "Phase", "Op", "Param", "Samples", "Time"],
        rows,
        "Full-election lifecycle timings (hand-rolled, deterministic seed 20260412).",
        "tab:g4_election_lifecycle",
    )


def g5_handrolled_vs_lib(timings: list[dict]) -> None:
    """Pair handrolled and lib measurements within *_compare groups."""
    groups = ("rep_compare", "dleq_compare", "encval_compare", "serval_compare", "bitvec_compare", "set_compare")
    by_key: dict[tuple[str, str, str], dict[str, dict]] = {}
    for r in timings:
        if r["group"] not in groups:
            continue
        # function looks like "prove/handrolled", "verify/lib", etc.
        if "/" not in r["function"]:
            continue
        op, mode = r["function"].split("/", 1)
        by_key.setdefault((r["group"], op, r["value"]), {})[mode] = r

    rows = []
    for (group, op, scale), modes in sorted(by_key.items()):
        hr = modes.get("handrolled")
        lib = modes.get("lib")
        if hr and lib and hr["mean_ns"] > 0:
            ratio = lib["mean_ns"] / hr["mean_ns"]
            rows.append(
                [
                    group,
                    op,
                    scale or "—",
                    fmt_time(hr["mean_ns"]),
                    fmt_time(lib["mean_ns"]),
                    f"{ratio:.2f}×",
                ]
            )
    write_pair(
        "g5_handrolled_vs_lib",
        ["Group", "Op", "Scale", "Hand-rolled", "Library", "lib / hand-rolled"],
        rows,
        "Hand-rolled vs library-backed prove/verify (statement-fidelity caveats noted in Section X).",
        "tab:g5_handrolled_vs_lib",
    )


def g6_tally_breakdown(timings: list[dict]) -> None:
    rows = []
    for r in timings:
        if not (r["group"].endswith("/tally") or r["group"].endswith("_tally")):
            continue
        m = N_FROM_GROUP.match(r["group"])
        if not m:
            continue
        n = int(m.group(1))
        rows.append(
            [
                f"{n:,}",
                r["function"] or "—",
                r["value"] or "—",
                f"{r['n_samples']}",
                fmt_time_pm(r["mean_ns"], r["ci_lo_ns"], r["ci_hi_ns"]),
            ]
        )
    rows.sort(key=lambda x: (int(x[0].replace(",", "")), x[1]))
    write_pair(
        "g6_tally_breakdown",
        ["N", "Op", "Param", "Samples", "Time"],
        rows,
        "Tally pipeline breakdown (per-tallier serial decryption, full pipeline).",
        "tab:g6_tally_breakdown",
    )


def main() -> int:
    TABLES.mkdir(parents=True, exist_ok=True)
    timings = load_timings()
    sizes = load_sizes()
    print(f"loaded {len(timings)} timing rows, {len(sizes)} size rows")

    g1_proof_primitives(timings)
    g2_proof_sizes(sizes)
    g3_batch_amortization(timings)
    g3b_election_batch_verify(timings)
    g4_election_lifecycle(timings)
    g5_handrolled_vs_lib(timings)
    g6_tally_breakdown(timings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
