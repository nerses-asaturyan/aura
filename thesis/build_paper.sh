#!/usr/bin/env bash
# Build paper.pdf from ./paper.tex (both live in thesis/).
#
# Requires:
#   * luahbtex (Debian/Ubuntu: texlive-binaries; engine for `lualatex`)
#   * texlive-luatex texmf tree (luaotfload, etc.)
#   * fontspec + polyglossia (texlive-latex-extra)
#   * FreeSerif OTF for Armenian script (FreeFont package)
#
# Notes
#   * Auto-falls back from xelatex to lualatex when xetex format is missing.
#   * Output paper.pdf is placed next to this script (i.e. in thesis/).
#   * Intermediate .aux/.log/.toc/.out land in thesis/build/ and are kept
#     between runs so the second pass can resolve refs without rebuilding
#     everything from scratch.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/paper.tex"
BUILD="$HERE/build"
OUT_PDF="$HERE/paper.pdf"

if [[ ! -f "$SRC" ]]; then
  echo "error: $SRC not found" >&2
  exit 1
fi

# Prefer xelatex (the document was authored for it). Fall back to lualatex,
# which supports the same fontspec + polyglossia stack and is what the
# default Linux TeX Live install has the format file for.
ENGINE=""
if command -v xelatex >/dev/null && kpsewhich -engine=xetex xelatex.fmt >/dev/null 2>&1; then
  ENGINE="xelatex"
elif command -v lualatex >/dev/null && kpsewhich -engine=luahbtex lualatex.fmt >/dev/null 2>&1; then
  ENGINE="lualatex"
else
  echo "error: neither xelatex nor lualatex is usable on this system" >&2
  exit 1
fi
echo "[paper] engine: $ENGINE"

mkdir -p "$BUILD"

run_engine() {
  local label="$1"
  echo "[paper] $label pass"
  ( cd "$BUILD" && "$ENGINE" \
      -interaction=nonstopmode \
      -halt-on-error \
      -jobname=paper \
      "$SRC" >/dev/null )
}

# Loop passes until LaTeX stops asking for a rerun (caps at 4 to be safe).
# Each pass writes to the same build/ tree so the prior .aux is read on the
# next iteration.
MAX_PASSES=4
for i in $(seq 1 "$MAX_PASSES"); do
  run_engine "pass $i"
  if [[ $i -ge 2 ]] && ! grep -q "Rerun to get" "$BUILD/paper.log"; then
    break
  fi
done

cp "$BUILD/paper.pdf" "$OUT_PDF"
echo "[paper] wrote $OUT_PDF ($(du -h "$OUT_PDF" | cut -f1), $(pdfinfo "$OUT_PDF" 2>/dev/null | awk '/^Pages/ {print $2" pages"}'))"
