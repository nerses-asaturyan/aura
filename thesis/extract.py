#!/usr/bin/env python3
"""Extract Criterion benchmark results into a tidy CSV.

Walks `target/criterion/` and reads every `<group>/<benchmark_id>/new/estimates.json`,
producing `thesis/results/timings.csv` with one row per (group, benchmark_id).

Also parses `thesis/results/raw/proof_sizes.log` (output of `cargo bench --bench
proof_sizes -- --quick`) into `thesis/results/sizes.csv`.

This script is idempotent: rerunning produces a byte-identical CSV given the
same Criterion state.
"""

from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRITERION_DIR = ROOT / "target" / "criterion"
RESULTS = ROOT / "thesis" / "results"
RAW = RESULTS / "raw"


def find_estimate_files(criterion_dir: Path) -> list[Path]:
    """Find every <something>/new/estimates.json under target/criterion/."""
    if not criterion_dir.exists():
        return []
    return sorted(p for p in criterion_dir.rglob("new/estimates.json"))


def find_benchmark_files(criterion_dir: Path) -> dict[Path, Path]:
    """Map <something>/new/estimates.json -> <something>/new/benchmark.json."""
    out: dict[Path, Path] = {}
    for ej in find_estimate_files(criterion_dir):
        bj = ej.parent / "benchmark.json"
        if bj.exists():
            out[ej] = bj
    return out


def parse_estimates(path: Path) -> dict[str, float | int]:
    """Pull mean point estimate, 95% CI bounds, and sample count."""
    data = json.loads(path.read_text())
    mean = data.get("mean", {})
    point = float(mean.get("point_estimate", float("nan")))
    ci = mean.get("confidence_interval", {})
    lo = float(ci.get("lower_bound", float("nan")))
    hi = float(ci.get("upper_bound", float("nan")))
    return {"mean_ns": point, "ci_lo_ns": lo, "ci_hi_ns": hi}


def parse_benchmark_meta(path: Path) -> dict[str, str | int]:
    data = json.loads(path.read_text())
    # Criterion stores the user-facing group + id in different fields across versions.
    group = data.get("group_id", data.get("group", ""))
    func = data.get("function_id", data.get("benchmark", ""))
    value = data.get("value_str", data.get("value", ""))
    full_id = data.get("full_id", "")
    # Sample count: read length of sample.json's `times` array if present.
    sample_path = path.parent / "sample.json"
    n_samples = 0
    if sample_path.exists():
        try:
            sd = json.loads(sample_path.read_text())
            n_samples = len(sd.get("times", []))
        except (json.JSONDecodeError, OSError):
            pass
    return {
        "group": group or "",
        "function": func or "",
        "value": value or "",
        "full_id": full_id,
        "n_samples": n_samples,
    }


def relative_id(estimate_path: Path) -> str:
    """Path relative to target/criterion/, dropping the trailing `/new/estimates.json`."""
    rel = estimate_path.relative_to(CRITERION_DIR)
    return str(rel.parent.parent).replace("\\", "/")


def write_timings_csv(rows: list[dict[str, str | int | float]]) -> Path:
    out = RESULTS / "timings.csv"
    fieldnames = [
        "group",
        "function",
        "value",
        "full_id",
        "criterion_path",
        "n_samples",
        "mean_ns",
        "ci_lo_ns",
        "ci_hi_ns",
    ]
    rows_sorted = sorted(rows, key=lambda r: (r["group"], r["function"], r["value"], r["criterion_path"]))
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows_sorted:
            w.writerow(row)
    return out


# ---------- Sizes (parsed from proof_sizes log) ----------

# Lines in the size report look like:
#   Representation (n=2):        96 B
#   N=256                :     2.8 KB
SIZE_LINE = re.compile(r"^\s*([^:]+?)\s*:\s*([\d,]+(?:\.\d+)?)\s*(B|KB|MB)\b", re.IGNORECASE)


def parse_sizes_log(log_path: Path) -> list[dict[str, str | int | float]]:
    """Extract every label/size pair from the proof_sizes.rs printed table.

    Heuristic: any line matching `<label>: <number> <unit>` is captured. A
    `section` column is derived from the most recently seen ALL-CAPS heading.
    """
    rows: list[dict[str, str | int | float]] = []
    if not log_path.exists():
        return rows
    section = ""
    for raw in log_path.read_text(errors="replace").splitlines():
        line = raw.rstrip()
        # Heading: any non-blank line that's mostly uppercase letters.
        stripped = line.strip()
        if stripped and not stripped[:1].isspace() and len(stripped) >= 4:
            letters = [c for c in stripped if c.isalpha()]
            if letters and sum(1 for c in letters if c.isupper()) / len(letters) > 0.7:
                if not SIZE_LINE.match(line):
                    section = stripped
                    continue
        m = SIZE_LINE.match(line)
        if m:
            label = m.group(1).strip()
            num = float(m.group(2).replace(",", ""))
            unit = m.group(3).upper()
            mult = {"B": 1, "KB": 1024, "MB": 1024 * 1024}[unit]
            bytes_value = int(round(num * mult))
            rows.append(
                {
                    "section": section,
                    "label": label,
                    "raw_value": f"{m.group(2)} {unit}",
                    "bytes": bytes_value,
                }
            )
    return rows


def write_sizes_csv(rows: list[dict[str, str | int | float]]) -> Path:
    out = RESULTS / "sizes.csv"
    fieldnames = ["section", "label", "raw_value", "bytes"]
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in rows:
            w.writerow(row)
    return out


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)

    pairs = find_benchmark_files(CRITERION_DIR)
    if not pairs:
        print(f"No criterion outputs found under {CRITERION_DIR}", file=sys.stderr)

    rows: list[dict[str, str | int | float]] = []
    for est_path, bench_path in pairs.items():
        est = parse_estimates(est_path)
        meta = parse_benchmark_meta(bench_path)
        rows.append(
            {
                "group": meta["group"],
                "function": meta["function"],
                "value": meta["value"],
                "full_id": meta["full_id"],
                "criterion_path": relative_id(est_path),
                "n_samples": meta["n_samples"],
                "mean_ns": est["mean_ns"],
                "ci_lo_ns": est["ci_lo_ns"],
                "ci_hi_ns": est["ci_hi_ns"],
            }
        )
    timings_path = write_timings_csv(rows)
    print(f"wrote {timings_path}  ({len(rows)} rows)")

    size_rows = parse_sizes_log(RAW / "proof_sizes.log")
    sizes_path = write_sizes_csv(size_rows)
    print(f"wrote {sizes_path}    ({len(size_rows)} rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
