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
  proofs/           6 proving systems (representation, DLEQ, enc validity,
                    serial validity, bit vector, commitment set)
  elgamal/          Threshold ElGamal (encrypt, partial decrypt, BSGS dlog)
  dkg/              Pedersen distributed key generation
  signature.rs      Context-bound Schnorr signatures
  election/         Protocol orchestration (setup, ballot, tally, bulletin board)
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
cargo test
```

Output: 59 tests across unit tests and integration tests.

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

| Suite | Command | What it measures | Time estimate |
|---|---|---|---|
| **Proof primitives** | `cargo bench --bench proof_primitives` | All 6 proof types, bit vector scaling, set proof scaling, batch verify (rep, dleq, encval) | ~10 min |
| **Proof sizes** | `cargo bench --bench proof_sizes -- --quick` | Byte sizes of all proofs and ballots (instant, no timing) | ~5 sec |
| **Election N=16** | `cargo bench --bench election_n16` | Full election: DKG, voter reg, ballot, batch verify (individual + batched encval), tally | ~2 min |
| **Election N=64** | `cargo bench --bench election_n64` | Full election | ~3 min |
| **Election N=256** | `cargo bench --bench election_n256` | Full election | ~8 min |
| **Election N=1,024** | `cargo bench --bench election_n1024` | Full election | ~20 min |
| **Election N=4,096** | `cargo bench --bench election_n4096` | Full election | ~40 min |
| **Election N=16,384** | `cargo bench --bench election_n16384` | Full election | ~1.5 hr |
| **Election N=65,536** | `cargo bench --bench election_n65536` | Full election | ~3 hr |
| **Election N=262,144** | `cargo bench --bench election_n262144` | Ballot create/verify + set proof only | ~30 min |
| **Election N=1,048,576** | `cargo bench --bench election_n1048576` | Ballot create/verify + set proof only | ~2 hr |

> **Note**: For N >= 262,144, only ballot-level operations are benchmarked (creating all N ballots for a full tally would be prohibitively slow). For N <= 65,536, the full pipeline is measured including DKG, tally serial decryption, and tally result computation.

### Run all benchmarks

```bash
cargo bench
```

> **Warning**: Running all suites end-to-end takes many hours. Run individual suites instead.

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
# 1. Proof sizes (instant)
cargo bench --bench proof_sizes -- --quick

# 2. Individual proof costs (~5 min)
cargo bench --bench proof_primitives

# 3. Small-scale full elections (~10 min total)
cargo bench --bench election_n16
cargo bench --bench election_n64
cargo bench --bench election_n256

# 4. Medium-scale full elections (~1 hr total)
cargo bench --bench election_n1024
cargo bench --bench election_n4096

# 5. Large-scale ballot operations (~1-3 hr total)
cargo bench --bench election_n16384
cargo bench --bench election_n65536
cargo bench --bench election_n262144
cargo bench --bench election_n1048576
```

---

## References

- Jivanyan, A., Feickert, A. (2022). *Aura: private voting with reduced trust on tallying authorities*. [ePrint 2022/543](https://eprint.iacr.org/2022/543)
- Bootle, J. et al. (2015). *Short Accountable Ring Signatures Based on DDH*. ESORICS 2015.
- Jivanyan, A., Feickert, A. (2021). *Lelantus Spark*. [ePrint 2021/1173](https://eprint.iacr.org/2021/1173)

## License

BSD-3-Clause
