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

## Usage

```bash
cargo test              # Run 59 tests
cargo test --release    # Fast run
cargo bench             # Full benchmark suite (scales to 2^20 voters)
cargo clippy            # Lint
```

## Cryptographic Stack

- **Group**: Ristretto255 via `curve25519-dalek` (prime-order, DDH-hard, constant-time)
- **Transcripts**: Merlin (Fiat-Shamir transform)
- **MSM**: Pippenger's algorithm via `curve25519-dalek::vartime_multiscalar_mul`

## Benchmarks

Benchmarks cover individual proof types, scaling curves (N = 4 to 2^20 voters), batch verification amortization, DKG scaling, and full election tally pipelines.

```bash
cargo bench --bench proofs      # Proof benchmarks
cargo bench --bench election    # Election benchmarks
```

HTML reports with plots are generated in `target/criterion/`.

## References

- Jivanyan, A., Feickert, A. (2022). *Aura: private voting with reduced trust on tallying authorities*. [ePrint 2022/543](https://eprint.iacr.org/2022/543)
- Bootle, J. et al. (2015). *Short Accountable Ring Signatures Based on DDH*. ESORICS 2015.
- Jivanyan, A., Feickert, A. (2021). *Lelantus Spark*. [ePrint 2021/1173](https://eprint.iacr.org/2021/1173)

## License

BSD-3-Clause
