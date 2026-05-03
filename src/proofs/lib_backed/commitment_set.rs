//! Library-backed one-of-many membership proof via the vendored
//! `one-of-many-proofs` crate (Bootle et al. ESORICS 2015 — plain Bootle, not
//! the Spark-modified variant Aura's hand-rolled proof uses).
//!
//! Stack: `one-of-many-proofs` 0.1 + `curve25519-dalek` 2 + `merlin` 2,
//! vendored into `vendor/one-of-many-proofs` and patched to disable
//! `simd_backend`/`nightly` features (those pulled in `packed_simd_2` which
//! does not compile on stable rustc).
//!
//! ## Statement-fidelity caveats (relevant for the thesis benchmark)
//!
//! The library does **not** accept user-supplied commitment generators.
//! Internally it uses `G = RISTRETTO_BASEPOINT_POINT` and
//! `H[0] = SHA3-512(G)` to build its own Pedersen scheme. Aura's
//! `CommitmentSetParams::g` and `params::h` are therefore ignored: the
//! library proof is in terms of the library's generators, not Aura's.
//!
//! As a consequence:
//! * The lib-backed `prove` recomputes `c_prime` internally using the
//!   library's basepoint, ignoring `statement.c_prime` from the call site.
//!   The library `c_prime` is stored on the proof so the verifier can
//!   re-derive it bit-exact.
//! * The library only supports set sizes that are exact powers of two.
//!   `params.n.pow(params.m)` must equal `2^k` for some `k` ≤ 32.
//!
//! Both deviations are expected for a "library replacement" benchmark and
//! should be disclosed alongside the timings.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript as MerlinV3;
use rand_core::CryptoRngCore;

use one_of_many_proofs::proofs::{OneOfManyProof, OneOfManyProofs, ProofGens};

use crate::errors::{AuraError, AuraResult};
use crate::transcript::TranscriptProtocol;

use super::bridge::dalek_v2;

pub use crate::proofs::commitment_set::{
    CommitmentSetParams, CommitmentSetStatement, CommitmentSetWitness,
};

const PROOF_TYPE: &str = "commitment_set";
const AURA_DOMAIN: &[u8] = b"aura/lib-set/oneof-many/v1";

/// Library-backed commitment-set proof. Wraps the `OneOfManyProof` from the
/// vendored crate plus the library's `c_prime` (offset) so the verifier can
/// re-bind to the same offset used by the prover.
#[derive(Clone)]
pub struct CommitmentSetProof {
    pub inner: OneOfManyProof,
    /// Library-computed c_prime (offset) bytes — replaces `statement.c_prime`
    /// inside the lib-backed verify path.
    pub lib_c_prime: [u8; 32],
}

impl core::fmt::Debug for CommitmentSetProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommitmentSetProof").finish()
    }
}

/// Convert `n^m` into the library's `n_bits` (= log2 of the set size).
/// Returns `None` if the set size is not an exact power of two.
fn n_bits_for(params: &CommitmentSetParams) -> Option<usize> {
    let n = params.n as u64;
    let m = params.m as u32;
    let big_n = n.checked_pow(m)?;
    if big_n == 0 || (big_n & (big_n - 1)) != 0 {
        return None;
    }
    Some(big_n.trailing_zeros() as usize)
}

/// Squeeze a 64-byte challenge from Aura's merlin-3 transcript and label a
/// fresh merlin-2 transcript with it. Same trick as in the zkp-backed
/// modules — propagates Aura's protocol context into the lib's Fiat-Shamir.
fn rekey_v2_transcript(
    aura_transcript: &mut MerlinV3,
) -> merlin_v2::Transcript {
    aura_transcript.domain_sep(AURA_DOMAIN);
    let mut bind = [0u8; 64];
    aura_transcript.challenge_bytes(b"aura-bind", &mut bind);
    let mut t = merlin_v2::Transcript::new(b"aura-lib-backed");
    t.append_message(b"aura-bind", &bind);
    t
}

/// Bridge an Aura `RistrettoPoint` into a `dalek 2` `RistrettoPoint` via the
/// canonical 32-byte Ristretto255 encoding.
fn aura_point_to_v2(
    p: &RistrettoPoint,
) -> AuraResult<curve25519_dalek_v2::ristretto::RistrettoPoint> {
    dalek_v2::point_from_bytes(&p.compress().to_bytes(), PROOF_TYPE)
}

impl CommitmentSetProof {
    pub fn prove(
        statement: &CommitmentSetStatement,
        witness: &CommitmentSetWitness,
        transcript: &mut MerlinV3,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let n_bits = n_bits_for(&statement.params).ok_or_else(|| AuraError::InvalidParameter {
            reason: format!(
                "lib-backed commitment-set requires N = n^m to be a power of two; got {}^{}",
                statement.params.n, statement.params.m
            ),
        })?;
        let big_n = 1usize << n_bits;

        if statement.commitments.len() != big_n {
            return Err(AuraError::InvalidParameter {
                reason: format!(
                    "expected {} commitments, got {}",
                    big_n,
                    statement.commitments.len()
                ),
            });
        }

        let gens = ProofGens::new(n_bits).map_err(|_| AuraError::InvalidParameter {
            reason: "one-of-many-proofs: ProofGens::new failed".into(),
        })?;

        // Sample a fresh blinding via Aura's RNG (always canonical because
        // `Scalar::random` uses wide reduction), then bridge to the library's
        // dalek-2 scalar via canonical 32-byte encoding. The witness blinding
        // from Aura's call site is intentionally ignored — see module docstring.
        let _ = witness.blinding;
        let lib_blinding =
            dalek_v2::scalar_from_bytes(&Scalar::random(rng).to_bytes(), PROOF_TYPE)?;

        // Bridge commitments to dalek-2 points.
        let lib_commits: Vec<curve25519_dalek_v2::ristretto::RistrettoPoint> = statement
            .commitments
            .iter()
            .map(aura_point_to_v2)
            .collect::<AuraResult<_>>()?;

        // Compute lib c_prime = C_l - blinding * G (library basepoint).
        let secret_c_l = lib_commits[witness.index as usize];
        let g_basepoint =
            curve25519_dalek_v2::constants::RISTRETTO_BASEPOINT_POINT;
        let lib_c_prime_pt = secret_c_l - lib_blinding * g_basepoint;

        let mut lib_transcript = rekey_v2_transcript(transcript);

        let proof = lib_commits
            .iter()
            .prove_with_offset(
                &gens,
                &mut lib_transcript,
                witness.index as usize,
                &lib_blinding,
                Some(&lib_c_prime_pt),
            )
            .map_err(|_| AuraError::VerificationFailed {
                proof_type: "commitment_set",
            })?;

        Ok(CommitmentSetProof {
            inner: proof,
            lib_c_prime: dalek_v2::point_to_bytes(&lib_c_prime_pt),
        })
    }

    pub fn verify(
        &self,
        statement: &CommitmentSetStatement,
        transcript: &mut MerlinV3,
    ) -> AuraResult<()> {
        let n_bits = n_bits_for(&statement.params).ok_or_else(|| AuraError::InvalidParameter {
            reason: "lib-backed commitment-set requires N = power of two".into(),
        })?;
        let big_n = 1usize << n_bits;
        if statement.commitments.len() != big_n {
            return Err(AuraError::VerificationFailed {
                proof_type: "commitment_set",
            });
        }

        let gens = ProofGens::new(n_bits).map_err(|_| AuraError::VerificationFailed {
            proof_type: "commitment_set",
        })?;

        let lib_commits: Vec<curve25519_dalek_v2::ristretto::RistrettoPoint> = statement
            .commitments
            .iter()
            .map(aura_point_to_v2)
            .collect::<AuraResult<_>>()?;

        let lib_c_prime =
            dalek_v2::point_from_bytes(&self.lib_c_prime, PROOF_TYPE)?;

        let mut lib_transcript = rekey_v2_transcript(transcript);

        lib_commits
            .iter()
            .verify_batch_with_offsets(
                &gens,
                &mut lib_transcript,
                core::slice::from_ref(&self.inner),
                &[Some(&lib_c_prime)],
            )
            .map_err(|_| AuraError::VerificationFailed {
                proof_type: "commitment_set",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Construct a `CommitmentSetStatement` with `params.n^params.m` random
    /// commitments and a witness pointing at `secret_index`. The actual
    /// `c_prime` value in the statement is irrelevant to the lib-backed
    /// path (see module docstring); we set it to a placeholder.
    fn create_test_set(
        n: u32,
        m: u32,
        secret_index: u32,
        rng: &mut impl CryptoRngCore,
    ) -> (CommitmentSetStatement, CommitmentSetWitness) {
        let big_n = (n as usize).pow(m);
        let g = RistrettoPoint::random(rng);
        let h = RistrettoPoint::random(rng);

        let commitments: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| {
                let s = Scalar::random(rng);
                let r = Scalar::random(rng);
                s * g + r * h
            })
            .collect();

        let blinding = Scalar::random(rng);
        let placeholder_c_prime = commitments[secret_index as usize] - blinding * h;

        let params = CommitmentSetParams { n, m, g, h };
        (
            CommitmentSetStatement {
                params,
                commitments,
                c_prime: placeholder_c_prime,
            },
            CommitmentSetWitness {
                index: secret_index,
                blinding,
            },
        )
    }

    #[test]
    fn prove_and_verify_n2_m3() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 3, 5, &mut rng);
        let mut pt = MerlinV3::new(b"test-set-lib");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = MerlinV3::new(b"test-set-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_n2_m10() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 10, 500, &mut rng);
        let mut pt = MerlinV3::new(b"test-set-lib");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = MerlinV3::new(b"test-set-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_index_0() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 3, 0, &mut rng);
        let mut pt = MerlinV3::new(b"test-set-lib");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = MerlinV3::new(b"test-set-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn non_power_of_two_rejected() {
        let mut rng = OsRng;
        // n=3, m=2 → N=9 not a power of two
        let big_n = 9;
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);
        let commitments: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| Scalar::random(&mut rng) * g + Scalar::random(&mut rng) * h)
            .collect();
        let statement = CommitmentSetStatement {
            params: CommitmentSetParams { n: 3, m: 2, g, h },
            commitments,
            c_prime: g,
        };
        let witness = CommitmentSetWitness {
            index: 0,
            blinding: Scalar::random(&mut rng),
        };

        let mut pt = MerlinV3::new(b"test-set-lib");
        let result = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng);
        assert!(matches!(
            result,
            Err(AuraError::InvalidParameter { .. })
        ));
    }
}
