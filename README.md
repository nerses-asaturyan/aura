# Aura

Rust implementation of the **Aura** private voting protocol ([Jivanyan & Feickert, 2022](https://eprint.iacr.org/2022/543)).

Aura is an election protocol that dissociates ballots from voter identity cryptographically, uses verifiable encryption and threshold decryption, and requires no trusted setup.

## Features

- **Ballot privacy**: ElGamal encryption with threshold decryption
- **Voter anonymity**: One-out-of-N commitment set membership proofs (logarithmic size)
- **Coercion resistance**: Ballot recasting with encrypted serial numbers
- **Trust-free setup**: Pedersen DKG with Feldman commitments, no trusted dealer
- **Efficient proofs**: Batch-verifiable Schnorr-type proving systems
- **Universal verifiability**: Any observer can verify the election result

## Architecture

```
src/
  proofs/                6 proving systems (representation, DLEQ, enc validity,
                         serial validity, bit vector, commitment set)
    lib_backed/          Optional library-backed equivalents of the 6 proofs
                         (feature `lib-proofs`, see "Library-backed proofs" below)
  elgamal/               Threshold ElGamal (encrypt, partial decrypt, BSGS dlog)
  dkg/                   Pedersen distributed key generation
  signature.rs           Context-bound Schnorr signatures
  election/              Protocol orchestration (setup, ballot, tally, bulletin board)
vendor/
  one-of-many-proofs/    Vendored fork of cargodog/one-of-many-proofs, used by
                         `lib_backed::commitment_set`. Patched to drop the
                         `simd_backend`/`nightly` features (those pulled in
                         `packed_simd_2`, which no longer compiles on stable
                         rustc). MIT-licensed; original by cargodog.
```

## Cryptographic Stack

- **Group**: Ristretto255 via `curve25519-dalek` (prime-order, DDH-hard, constant-time)
- **Transcripts**: Merlin (Fiat-Shamir transform)
- **MSM**: Pippenger's algorithm via `curve25519-dalek::vartime_multiscalar_mul`

## Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Optional: `gnuplot` for higher-quality benchmark plots

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Optional: install gnuplot for benchmark HTML plots
sudo apt install gnuplot    # Debian/Ubuntu
brew install gnuplot         # macOS
```

---

## Tests

### Run all tests (debug mode)

```bash
cargo test                          # hand-rolled (default): 57 unit + 5 integration
cargo test --features lib-proofs    # adds 22 lib-backed unit tests → 79 + 5
```

Output: 62 tests by default; 84 with `lib-proofs` enabled.

### Run all tests (release mode, faster)

```bash
cargo test --release
```

### Run a specific test module

```bash
cargo test proofs::commitment_set     # all commitment set tests
cargo test proofs::bit_vector         # all bit vector tests
cargo test proofs::dleq               # DLEQ proof tests
cargo test proofs::representation     # representation proof tests
cargo test dkg::protocol              # DKG protocol tests
cargo test elgamal::decrypt           # ElGamal decryption tests
cargo test signature                  # signature tests
```

### Run integration tests only

```bash
cargo test --test full_election
```

This runs two end-to-end tests:
- `full_election_8_voters_3_talliers_4_candidates` — complete election flow
- `coercion_resistance_ballot_recast` — voter recasts ballot, old one is discarded

### Run a single test by name

```bash
cargo test full_election_8_voters
cargo test coercion_resistance
```

### Run tests with output (see println! output)

```bash
cargo test -- --nocapture
```

---

## Linting

```bash
cargo clippy -- -D warnings
```

---

## Benchmarks

All benchmarks use [Criterion.rs](https://bheisler.github.io/criterion.rs/book/) and compile in release mode automatically. Results include statistical analysis with confidence intervals and regression detection.

### Benchmark suites

| Suite | Command | What it measures |
|---|---|---|
| **Proof primitives** | `cargo bench --bench proof_primitives` | All 6 proof types, bit vector scaling, set proof scaling, batch verify (rep, dleq, encval) |
| **Proof sizes** | `cargo bench --bench proof_sizes -- --quick` | Byte sizes of all proofs and ballots |
| **Election N=16** | `cargo bench --bench election_n16` | Full election: DKG, voter reg, ballot, batch verify (individual + batched encval), tally |
| **Election N=64** | `cargo bench --bench election_n64` | Full election |
| **Election N=256** | `cargo bench --bench election_n256` | Full election |
| **Election N=1,024** | `cargo bench --bench election_n1024` | Full election |
| **Election N=4,096** | `cargo bench --bench election_n4096` | Full election |
| **Election N=16,384** | `cargo bench --bench election_n16384` | Full election |
| **Election N=65,536** | `cargo bench --bench election_n65536` | Full election |
| **Election N=262,144** | `cargo bench --bench election_n262144` | Ballot create/verify + set proof only |
| **Election N=1,048,576** | `cargo bench --bench election_n1048576` | Ballot create/verify + set proof only |
| **Lib comparison** | `cargo bench --bench proof_primitives_lib --features lib-proofs` | Hand-rolled vs library-backed prove/verify for all 6 proofs |

> **Note**: For N >= 262,144, only ballot-level operations are benchmarked. For N <= 65,536, the full pipeline is measured including DKG, tally serial decryption, and tally result computation.

### Run all benchmarks

```bash
cargo bench
```

> Running all suites end-to-end is slow. Prefer individual suites.

### Run a specific suite

```bash
cargo bench --bench election_n256
```

### Run a specific benchmark within a suite

```bash
cargo bench --bench election_n256 -- "ballot/create"
cargo bench --bench election_n256 -- "ballot/verify"
cargo bench --bench election_n256 -- "tally/full_pipeline"
cargo bench --bench election_n256 -- "tally/serial_decrypt"
cargo bench --bench election_n256 -- "dkg"
cargo bench --bench election_n256 -- "voter_registration"
cargo bench --bench election_n256 -- "verify_batch"
```

### Run proof primitives selectively

```bash
cargo bench --bench proof_primitives -- "representation"
cargo bench --bench proof_primitives -- "dleq"
cargo bench --bench proof_primitives -- "enc_validity"
cargo bench --bench proof_primitives -- "serial_validity"
cargo bench --bench proof_primitives -- "bit_vector"
cargo bench --bench proof_primitives -- "commitment_set"
```

### Batch verification benchmarks

Batch verification compresses multiple proof verification equations into a single multi-scalar multiplication (MSM) using random linear combination. This amortizes the per-proof cost as batch size grows — the key efficiency property described in Section 4.1 of the paper.

**Proof-level batch verification** (individual proof types, batch sizes 1-100):

```bash
# Representation proofs: individual vs batch
cargo bench --bench proof_primitives -- "batch_verify_rep"

# DLEQ proofs: individual vs batch
cargo bench --bench proof_primitives -- "batch_verify_dleq"

# Encryption validity proofs: individual vs batch
cargo bench --bench proof_primitives -- "batch_verify_encval"

# All three at once
cargo bench --bench proof_primitives -- "batch_verify"
```

**Cross-ballot batch verification** (collect all encryption validity proofs across N ballots, batch-verify in one MSM):

```bash
# At N=256: compare individual vs batched encval verification for 1/10/50/100 ballots
cargo bench --bench election_n256 -- "verify_batch_encval"

# At N=1024
cargo bench --bench election_n1024 -- "verify_batch_encval"
```

Each batch benchmark reports both `individual` (verify proofs one by one) and `batch` (single MSM call) timings at the same batch size, so you can directly compute the speedup factor.

### Save benchmark output to a file

```bash
cargo bench --bench election_n256 2>&1 | tee results_n256.txt
```

### View HTML reports

After running any benchmark, Criterion generates HTML reports with plots:

```bash
# Open the report index (Linux)
xdg-open target/criterion/report/index.html

# macOS
open target/criterion/report/index.html

# Or browse directly
ls target/criterion/
```

Each benchmark group gets its own subdirectory with:
- `report/index.html` — summary with violin plots
- `new/estimates.json` — raw timing data
- Comparison data if you run benchmarks multiple times

### Proof size report

Prints byte sizes for all proof types, full ballots at every scale, and a comparison with ElectionGuard:

```bash
cargo bench --bench proof_sizes -- --quick
```

Example output:

```
 INDIVIDUAL PROOF SIZES
  Representation (n=2):        96 B
  DLEQ:                        96 B
  Encryption validity:        128 B
  Serial validity:            192 B

 COMMITMENT SET PROOF SIZES (logarithmic in N)
  N=256                :     1,312 B
  N=65,536             :     2,592 B
  N=1,048,576          :     3,232 B

 FULL BALLOT SIZES (k=4, kmin=1, kmax=2)
  N=256                :     2.8 KB
  N=65,536             :     4.1 KB
  N=1,048,576          :     4.7 KB
```

### Recommended benchmark workflow

For a complete performance profile:

```bash
# 1. Proof sizes
cargo bench --bench proof_sizes -- --quick

# 2. Individual proof costs
cargo bench --bench proof_primitives

# 3. Small-scale full elections
cargo bench --bench election_n16
cargo bench --bench election_n64
cargo bench --bench election_n256

# 4. Medium-scale full elections
cargo bench --bench election_n1024
cargo bench --bench election_n4096

# 5. Large-scale ballot operations
cargo bench --bench election_n16384
cargo bench --bench election_n65536
cargo bench --bench election_n262144
cargo bench --bench election_n1048576
```

---

## Two implementations of the proofs

Each of the six proving systems has **two** parallel implementations in this crate:

1. **Hand-rolled** at [src/proofs/](src/proofs/) — the default. These reproduce the Aura paper's constructions directly: same statements, same transcript layout, same generators, same MSM strategy. This is what the protocol uses for all elections, ballots, DKG, and tally operations regardless of feature flags.
2. **Library-backed** at [src/proofs/lib_backed/](src/proofs/lib_backed/) — only compiled when the `lib-proofs` Cargo feature is enabled. Each proof delegates to an off-the-shelf Rust ZK library on its own native crypto stack, with byte-level bridging at the module boundary.

### Why both

- **Hand-rolled** is the paper-faithful reference. Every byte of every transcript and every generator choice matches the Aura paper, so the implementation can be audited line-by-line against the spec, and the protocol's correctness arguments carry over unchanged.
- **Library-backed** answers the practical question: *what would a developer get if they tried to build Aura on top of widely-used Rust ZK crates instead of writing the Sigma protocols by hand?* It surfaces the cost of (a) the library's overhead vs. a custom prover, (b) statement-fidelity compromises forced by the library's API, and (c) curve / transcript / RNG bridging when the library targets an older dalek line.

Comparing the two side-by-side gives prove/verify timings, proof sizes, and a concrete sense of which library replacements are clean drop-ins versus which require substantive deviations from the paper's statement.

### Library mapping

| # | Proof | Library | Crypto stack | Bridged? |
|---|---|---|---|---|
| 1 | Representation | [`zkp` 0.8](https://crates.io/crates/zkp) | `curve25519-dalek-ng` 3 / `merlin` 2 / `rand` 0.7 | yes |
| 2 | DLEQ | [`sigma-protocols` 0.5](https://crates.io/crates/sigma-protocols) | `curve25519-dalek` 4.1 | no |
| 3 | EncryptionValidity | [`zkp` 0.8](https://crates.io/crates/zkp) | `curve25519-dalek-ng` 3 / `merlin` 2 / `rand` 0.7 | yes |
| 4 | SerialValidity | [`zkp` 0.8](https://crates.io/crates/zkp) | `curve25519-dalek-ng` 3 / `merlin` 2 / `rand` 0.7 | yes |
| 5 | BitVector | [`bulletproofs` 5 (R1CS)](https://github.com/zkcrypto/bulletproofs) | `curve25519-dalek` 4.1 / `merlin` 3 | no |
| 6 | One-of-N | [`one-of-many-proofs` 0.1](https://docs.rs/one-of-many-proofs) (vendored) | `curve25519-dalek` 2 / `merlin` 2 / `rand` 0.7 | yes |

"Bridged" means the library lives on a different curve/transcript stack than Aura's home (`curve25519-dalek` 4.1 + `merlin` 3). For those proofs, the lib_backed module converts at the API boundary via the canonical 32-byte Ristretto255 / Scalar encoding (RFC 9496) and re-keys the library's transcript with a 64-byte challenge squeezed from Aura's merlin-3 transcript. The bridge module is at [src/proofs/lib_backed/bridge.rs](src/proofs/lib_backed/bridge.rs).

Bulletproofs is pinned to git/main (not crates.io 5.0.0) because the released version's R1CS code uses a pre-`CtOption` `Scalar::from_canonical_bytes` API that does not compile against `curve25519-dalek` 4.1.

### Statement-fidelity caveats

Two of the six library-backed proofs do not prove the **exact** statement of the hand-rolled paper construction:

- **#5 BitVector (bulletproofs R1CS)**: certifies the predicate (each `b_i ∈ {0,1}`, `Σ b_i = w`) over per-bit Pedersen commitments using bulletproofs' default `PedersenGens`, **without** binding to Aura's vector commitment `B = r·H + Σ b_i·G_i`. The hand-rolled proof additionally binds to `B`.
- **#6 One-of-N (`one-of-many-proofs`)**: uses the library's hardcoded basepoint `G = RISTRETTO_BASEPOINT_POINT` (not Aura's `params.h`), only supports set sizes that are exact powers of two, and recomputes `c_prime` internally using the library's basepoint — the lib-backed `c_prime` is stored on the proof, separate from `statement.c_prime`. The hand-rolled proof uses Aura's generators and the Spark-modified Bootle construction.

These are documented in module docstrings ([bit_vector.rs](src/proofs/lib_backed/bit_vector.rs), [commitment_set.rs](src/proofs/lib_backed/commitment_set.rs)) and should be disclosed alongside any timing comparison.

### Running each implementation exactly

Without the `lib-proofs` feature, only the hand-rolled proofs are even compiled — there is no possibility of accidentally exercising the library-backed path.

#### Hand-rolled only (default, paper-faithful)

```bash
# Tests for every hand-rolled proof + the full protocol (DKG, ballots, tally)
cargo test

# Hand-rolled proof primitives, all six types
cargo bench --bench proof_primitives

# Hand-rolled proof in any election bench
cargo bench --bench election_n256
```

The protocol's call sites in [src/election/ballot.rs](src/election/ballot.rs), [src/elgamal/decrypt.rs](src/elgamal/decrypt.rs), [src/dkg/protocol.rs](src/dkg/protocol.rs), and [src/election/setup.rs](src/election/setup.rs) all import from `crate::proofs::*` (hand-rolled) directly, so every full-election test and every election bench exercises the hand-rolled path — even when the `lib-proofs` feature is on.

#### Library-backed only

```bash
# Run only the lib-backed unit tests (22 tests, one module per proof)
cargo test --features lib-proofs proofs::lib_backed

# Or one specific lib-backed proof:
cargo test --features lib-proofs proofs::lib_backed::dleq
cargo test --features lib-proofs proofs::lib_backed::commitment_set

# Skip-run any lib-backed test from outside, e.g.:
cargo test --features lib-proofs --lib proofs::lib_backed::bit_vector::tests::large_k
```

#### Hand-rolled vs library-backed (side-by-side)

```bash
cargo bench --bench proof_primitives_lib --features lib-proofs
```

Each Criterion group runs four cases per proof type: `prove/handrolled`, `prove/lib`, `verify/handrolled`, `verify/lib`. Groups available: `rep_compare`, `dleq_compare`, `encval_compare`, `serval_compare`, `bitvec_compare`, `set_compare`.

Filter to a single proof:

```bash
cargo bench --bench proof_primitives_lib --features lib-proofs -- 'dleq_compare'
cargo bench --bench proof_primitives_lib --features lib-proofs -- 'set_compare'
```

## References

- Jivanyan, A., Feickert, A. (2022). *Aura: private voting with reduced trust on tallying authorities*. [ePrint 2022/543](https://eprint.iacr.org/2022/543)
- Bootle, J. et al. (2015). *Short Accountable Ring Signatures Based on DDH*. ESORICS 2015.
- Jivanyan, A., Feickert, A. (2021). *Lelantus Spark*. [ePrint 2021/1173](https://eprint.iacr.org/2021/1173)

## License

BSD-3-Clause
