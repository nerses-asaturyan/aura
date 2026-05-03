#!/usr/bin/env bash
# Aura thesis benchmark runner.
#
# Usage:  bash thesis/run_benches.sh {quick|standard|full}
#
# Captures hardware/toolchain metadata to thesis/results/env.txt, then runs the
# right subset of `cargo bench` invocations. Each run's stdout is teed into
# thesis/results/raw/.

set -uo pipefail

TIER="${1:-quick}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/thesis/results"
RAW="$RESULTS/raw"
mkdir -p "$RAW"

# ---------- Environment metadata ----------
echo "Capturing environment metadata..."
{
    echo "=== Date ==="
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    echo
    echo "=== Tier ==="
    echo "$TIER"
    echo
    echo "=== Deterministic seed ==="
    echo "ChaCha20Rng::seed_from_u64(20260412)  (benches/proof_primitives.rs:32, benches/bench_common.rs:20, benches/bench_large.rs:15)"
    echo
    echo "=== uname -a ==="
    uname -a
    echo
    echo "=== lscpu ==="
    lscpu 2>/dev/null || echo "(lscpu unavailable)"
    echo
    echo "=== free -h ==="
    free -h 2>/dev/null || echo "(free unavailable)"
    echo
    echo "=== rustc --version ==="
    rustc --version
    echo
    echo "=== cargo --version ==="
    cargo --version
    echo
    echo "=== git rev-parse HEAD ==="
    (cd "$ROOT" && git rev-parse HEAD 2>/dev/null) || echo "(not a git repo)"
    echo
    echo "=== git status (porcelain) ==="
    (cd "$ROOT" && git status --porcelain 2>/dev/null) || true
} > "$RESULTS/env.txt"

(cd "$ROOT" && cargo tree --features lib-proofs > "$RESULTS/deps.txt" 2>/dev/null) || true

run() {
    local name="$1"
    shift
    local logfile="$RAW/$name.log"
    echo
    echo "==> $name"
    echo "    cargo bench $* | tee $logfile"
    (cd "$ROOT" && cargo bench "$@" 2>&1) | tee "$logfile"
}

# ---------- Always run ----------
run proof_sizes --bench proof_sizes -- --quick
run proof_primitives --bench proof_primitives
run proof_primitives_lib --bench proof_primitives_lib --features lib-proofs

# ---------- Per tier ----------
case "$TIER" in
    quick)
        run election_n16  --bench election_n16
        run election_n64  --bench election_n64
        run election_n256 --bench election_n256
        ;;
    standard)
        run election_n16   --bench election_n16
        run election_n64   --bench election_n64
        run election_n256  --bench election_n256
        run election_n1024 --bench election_n1024
        run election_n4096 --bench election_n4096
        ;;
    full)
        run election_n16      --bench election_n16
        run election_n64      --bench election_n64
        run election_n256     --bench election_n256
        run election_n1024    --bench election_n1024
        run election_n4096    --bench election_n4096
        run election_n16384   --bench election_n16384
        run election_n65536   --bench election_n65536
        run election_n262144  --bench election_n262144
        run election_n1048576 --bench election_n1048576
        ;;
    *)
        echo "Unknown tier '$TIER'. Use quick | standard | full." >&2
        exit 2
        ;;
esac

echo
echo "All benches done. Logs in $RAW/. Now run:"
echo "    python3 thesis/extract.py"
echo "    python3 thesis/make_tables.py"
echo "    python3 thesis/make_plots.py"
