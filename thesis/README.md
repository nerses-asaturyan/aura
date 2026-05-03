# Thesis benchmark workflow

Reproducible pipeline that runs the Aura benches, extracts Criterion JSON into
tidy CSVs, and emits LaTeX/Markdown tables and PDF/PNG plots ready to drop
into a thesis manuscript.

## Quickstart

```bash
# Tier picks how far up the N axis to go. 'quick' covers N up to 256.
bash thesis/run_benches.sh quick      # runs ~30 min on a modern laptop

# Convert criterion JSON → CSVs
python3 thesis/extract.py

# CSVs → LaTeX (booktabs) + Markdown tables under thesis/results/tables/
python3 thesis/make_tables.py

# CSVs → PDF + PNG plots under thesis/results/plots/
python3 thesis/make_plots.py
```

## Tiers

| Tier       | N values covered           | What it includes                                         |
| ---------- | -------------------------- | -------------------------------------------------------- |
| `quick`    | 16, 64, 256                | All bench files except `election_n1024+`                 |
| `standard` | 16, 64, 256, 1024, 4096    | All bench files except `election_n16384+`                |
| `full`     | 16 … 1,048,576             | Every bench file, no exclusions                          |

`extract.py`, `make_tables.py`, and `make_plots.py` work on whatever is in
`target/criterion/` — partial runs produce partial outputs, no errors.

## Output layout

```
thesis/
  run_benches.sh
  extract.py
  make_tables.py
  make_plots.py
  results/
    env.txt          ← uname/lscpu/free/rustc/cargo/git, captured at run start
    deps.txt         ← `cargo tree --features lib-proofs`
    raw/             ← stdout of each `cargo bench` invocation
    timings.csv      ← (group, function, value, criterion_path, n_samples, mean_ns, ci_lo_ns, ci_hi_ns)
    sizes.csv        ← from proof_sizes.rs printed table
    tables/          ← g1…g6 tables, .tex (booktabs) + .md
    plots/           ← g3, g4, g5 plots, .pdf + .png
```

## Logical groups

| Group | What it covers                                                              | Source benches                                                |
| ----- | --------------------------------------------------------------------------- | ------------------------------------------------------------- |
| G1    | Per-proof prove/verify timings (hand-rolled)                                | `proof_primitives`                                            |
| G2    | Proof and ballot byte sizes                                                 | `proof_sizes`                                                 |
| G3    | Batch-verify amortization vs batch size                                     | `proof_primitives` (batch_verify_*) + election_n* batch encval |
| G4    | Full-election lifecycle vs N (DKG, voter, ballot, tally)                    | `election_n16` … `election_n1048576`                           |
| G5    | Hand-rolled vs library-backed prove/verify per proof                        | `proof_primitives_lib` (requires `--features lib-proofs`)      |
| G6    | Tally pipeline breakdown (per-tallier serial decryption, full pipeline)     | tally subgroup of every `election_n*`                          |

## Determinism

All benches use `ChaCha20Rng::seed_from_u64(20260412)` (see
`benches/proof_primitives.rs:32`, `benches/bench_common.rs:20`,
`benches/bench_large.rs:15`). Re-running with the same toolchain on the same
hardware produces means within Criterion's reported confidence intervals.

`env.txt` records the exact hardware/toolchain so the thesis can quote it
verbatim in the experimental-setup section.

## Statement-fidelity disclosures (G5)

When the thesis presents G5 (hand-rolled vs library-backed), it must disclose:

- **#5 BitVector** — the `bulletproofs` R1CS variant proves the predicate
  (each `b_i ∈ {0,1}`, `Σ b_i = w`) over per-bit Pedersen commitments using
  `bulletproofs`' default generators. It does **not** bind to Aura's vector
  commitment `B = r·H + Σ b_i·G_i`. The hand-rolled proof additionally binds
  to `B`. (See `src/proofs/lib_backed/bit_vector.rs` module docstring.)
- **#6 One-of-N** — `one-of-many-proofs` uses its own basepoint
  (`RISTRETTO_BASEPOINT_POINT`), only supports power-of-two set sizes, and
  recomputes its own `c_prime`. It is plain Bootle, not the Spark-modified
  variant from the Aura paper. (See
  `src/proofs/lib_backed/commitment_set.rs` module docstring.)
- **Curve confound** — `zkp` runs on `curve25519-dalek-ng 3` while Aura is on
  `curve25519-dalek 4.1`. The G5 timings therefore conflate "proof system"
  with "curve implementation"; report this honestly in the thesis.
