#!/usr/bin/env bash
# Convert a hand-picked set of Criterion SVG plots into PDFs that the LaTeX
# document includes via \includegraphics. Output goes to
# thesis/results/plots/criterion/.
#
# Picks (AWS run, source-of-truth for the main empirical chapter):
#   commitment_set         violin   — set-membership prove/verify across N
#   bit_vector             violin   — bit-vector scaling
#   batch_verify_encval    lines    — individual vs batched amortization
#   N16384_ballot          violin   — ballot create+verify distributions at N=16384
#   N16384_tally/full_pipeline pdf  — full tally pipeline at N=16384
#   representation         violin   — Schnorr representation prove/verify
#
# Converter: cairosvg (Python module, installed --user). No system packages.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRIT="$HERE/results/criterion"
OUT="$HERE/results/plots/criterion"

mkdir -p "$OUT"

# (source path under criterion/, output base name)
PICKS=(
  "commitment_set/report/violin.svg                       commitment_set_violin"
  "bit_vector/report/violin.svg                            bit_vector_violin"
  "batch_verify_encval/report/lines.svg                    batch_verify_encval_lines"
  "N16384_ballot/report/violin.svg                         N16384_ballot_violin"
  "N16384_tally/full_pipeline/report/pdf.svg               N16384_tally_full_pipeline_pdf"
  "representation/report/violin.svg                        representation_violin"
)

convert_one() {
  local src="$1" dest="$2"
  if [[ ! -f "$src" ]]; then
    echo "  missing: $src" >&2
    return 1
  fi
  if [[ "$dest" -nt "$src" ]]; then
    return 0
  fi
  python3 -c "import cairosvg, sys; cairosvg.svg2pdf(url=sys.argv[1], write_to=sys.argv[2])" "$src" "$dest"
  echo "  wrote $(basename "$dest")"
}

for entry in "${PICKS[@]}"; do
  read -r rel name <<< "$entry"
  convert_one "$CRIT/$rel" "$OUT/${name}.pdf"
done
