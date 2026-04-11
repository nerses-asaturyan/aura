//! ElGamal threshold decryption.
//!
//! Each tallier produces a partial decryption with a DLEQ proof.
//! A threshold of partial decryptions can be combined to recover the message.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use crate::errors::{AuraError, AuraResult};
use crate::proofs::dleq::{DleqProof, DleqStatement, DleqWitness};
use crate::types::{Ciphertext, TallierIndex};

use super::keys::{KeyShare, PublicKeyShare};

/// A tallier's partial decryption of a ciphertext.
#[derive(Debug, Clone)]
pub struct PartialDecryption {
    /// Which tallier produced this.
    pub tallier: TallierIndex,
    /// Partial decryption point `R_alpha = y_alpha * D`.
    pub partial: RistrettoPoint,
    /// DLEQ proof that `R_alpha / D == Y_alpha / G`.
    pub proof: DleqProof,
}

impl PartialDecryption {
    /// Create a partial decryption for a ciphertext.
    ///
    /// Proves that `R_alpha = y_alpha * D` using a DLEQ proof
    /// showing `log_G(Y_alpha) == log_D(R_alpha)`.
    pub fn create(
        key_share: &KeyShare,
        ciphertext: &Ciphertext,
        base_generator: &RistrettoPoint,
        public_share_point: &RistrettoPoint,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let r_alpha = key_share.share * ciphertext.d;

        let statement = DleqStatement {
            g: *base_generator,
            h: ciphertext.d,
            y: *public_share_point,
            y_prime: r_alpha,
        };
        let witness = DleqWitness {
            scalar: key_share.share,
        };

        let proof = DleqProof::prove(&statement, &witness, transcript, rng)?;

        Ok(PartialDecryption {
            tallier: key_share.index,
            partial: r_alpha,
            proof,
        })
    }

    /// Verify a partial decryption.
    pub fn verify(
        &self,
        ciphertext: &Ciphertext,
        base_generator: &RistrettoPoint,
        public_share: &PublicKeyShare,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let statement = DleqStatement {
            g: *base_generator,
            h: ciphertext.d,
            y: public_share.point,
            y_prime: self.partial,
        };
        self.proof.verify(&statement, transcript)
    }
}

/// Compute Lagrange coefficient for player `j` within the given set of indices.
///
/// `lambda_j = prod_{i in indices, i != j} (i / (i - j))`
///
/// All indices are converted from `TallierIndex` (1-indexed u32) to `Scalar`.
fn lagrange_coefficient(j: TallierIndex, indices: &[TallierIndex]) -> Scalar {
    let j_scalar = j.to_scalar();
    let mut lambda = Scalar::ONE;
    for &i in indices {
        if i == j {
            continue;
        }
        let i_scalar = i.to_scalar();
        // lambda *= i / (i - j)
        let num = i_scalar;
        let den = i_scalar - j_scalar;
        lambda *= num * den.invert();
    }
    lambda
}

/// Combine partial decryptions to recover the message point `M`.
///
/// Returns `M = E - sum(lambda_j * R_j)` where `lambda_j` are Lagrange coefficients.
/// The actual message value must be recovered from `M` using `solve_dlog`.
pub fn combine_partial_decryptions(
    ciphertext: &Ciphertext,
    partials: &[PartialDecryption],
) -> RistrettoPoint {
    let indices: Vec<TallierIndex> = partials.iter().map(|p| p.tallier).collect();

    let shared_secret: RistrettoPoint = partials
        .iter()
        .map(|p| {
            let lambda = lagrange_coefficient(p.tallier, &indices);
            lambda * p.partial
        })
        .sum();

    ciphertext.e - shared_secret
}

/// Recover a small discrete log using baby-step giant-step.
///
/// Finds `m >= 0` such that `m * generator == target`, searching up to `max_value`.
/// Returns `None` if no such `m` exists.
pub fn solve_dlog(
    target: &RistrettoPoint,
    generator: &RistrettoPoint,
    max_value: u64,
) -> Option<u64> {
    if *target == RistrettoPoint::identity() {
        return Some(0);
    }

    // Baby-step giant-step.
    // Baby step size: ceil(sqrt(max_value + 1))
    let step_size = ((max_value as f64 + 1.0).sqrt().ceil()) as u64;

    // Baby steps: compute i*generator for i in [0, step_size)
    let mut baby_steps = std::collections::HashMap::new();
    let mut current = RistrettoPoint::identity();
    for i in 0..step_size {
        baby_steps.insert(current.compress(), i);
        current += generator;
    }

    // Giant step: step_size * generator
    let giant_step = Scalar::from(step_size) * generator;
    // Invert for subtraction: we want target - j*giant_step
    let neg_giant_step = -giant_step;

    let mut gamma = *target;
    for j in 0..=step_size {
        if let Some(&i) = baby_steps.get(&gamma.compress()) {
            let m = j * step_size + i;
            if m <= max_value {
                return Some(m);
            }
        }
        gamma += neg_giant_step;
    }

    None
}

/// Verify partial decryptions and combine to recover the message value.
///
/// This is the complete `VerifyDecrypt` from the paper.
pub fn verify_and_decrypt(
    ciphertext: &Ciphertext,
    partials: &[PartialDecryption],
    public_shares: &[PublicKeyShare],
    base_generator: &RistrettoPoint,
    message_generator: &RistrettoPoint,
    max_value: u64,
    transcripts: &mut [Transcript],
) -> AuraResult<u64> {
    if partials.len() != transcripts.len() {
        return Err(AuraError::InvalidParameter {
            reason: "mismatched partial decryptions and transcripts".into(),
        });
    }

    // Verify each partial decryption
    for (partial, transcript) in partials.iter().zip(transcripts.iter_mut()) {
        let share = public_shares
            .iter()
            .find(|s| s.index == partial.tallier)
            .ok_or(AuraError::InvalidParameter {
                reason: "unknown tallier index".into(),
            })?;
        partial.verify(ciphertext, base_generator, share, transcript)?;
    }

    // Combine partial decryptions
    let message_point = combine_partial_decryptions(ciphertext, partials);

    // Solve discrete log
    solve_dlog(&message_point, message_generator, max_value).ok_or(AuraError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    use crate::elgamal::keys::ElectionPublicKey;
    use crate::proofs::representation::{
        RepresentationProof, RepresentationStatement, RepresentationWitness,
    };

    /// Helper: create a simple 1-of-1 threshold setup and encrypt/decrypt.
    #[test]
    fn encrypt_decrypt_threshold_1() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let h_i = RistrettoPoint::random(&mut rng);

        // Single tallier key
        let sk = Scalar::random(&mut rng);
        let pk_point = sk * g;

        let key_share = KeyShare {
            index: TallierIndex(1),
            share: sk,
        };

        // Create a trivial public share proof
        let share_statement = RepresentationStatement {
            generators: vec![g],
            target: pk_point,
        };
        let share_witness = RepresentationWitness {
            scalars: vec![sk],
        };
        let mut share_transcript = Transcript::new(b"test-keygen");
        let share_proof = RepresentationProof::prove(
            &share_statement,
            &share_witness,
            &mut share_transcript,
            &mut rng,
        )
        .unwrap();

        let public_share = PublicKeyShare {
            index: TallierIndex(1),
            point: pk_point,
            proof: share_proof,
        };

        let election_key = ElectionPublicKey(pk_point);

        // Encrypt message = 7
        let msg = Scalar::from(7u64);
        let r = Scalar::random(&mut rng);
        let ct = Ciphertext {
            d: r * g,
            e: r * election_key.0 + msg * h_i,
        };

        // Partial decrypt
        let mut pd_transcript = Transcript::new(b"test-dec");
        let partial =
            PartialDecryption::create(&key_share, &ct, &g, &pk_point, &mut pd_transcript, &mut rng)
                .unwrap();

        // Verify and decrypt
        let mut verify_transcripts = vec![Transcript::new(b"test-dec")];
        let result = verify_and_decrypt(
            &ct,
            &[partial],
            &[public_share],
            &g,
            &h_i,
            100,
            &mut verify_transcripts,
        )
        .unwrap();

        assert_eq!(result, 7);
    }

    /// Test 2-of-3 threshold decryption.
    #[test]
    fn encrypt_decrypt_threshold_2_of_3() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let h_i = RistrettoPoint::random(&mut rng);

        // Simulate Shamir secret sharing with threshold t=2, n=3
        // Secret polynomial: f(x) = a0 + a1*x
        let a0 = Scalar::random(&mut rng);
        let a1 = Scalar::random(&mut rng);

        let share1 = a0 + a1 * Scalar::from(1u64);
        let share2 = a0 + a1 * Scalar::from(2u64);
        let share3 = a0 + a1 * Scalar::from(3u64);

        // The actual secret key is a0
        let election_key = ElectionPublicKey(a0 * g);

        // Create key shares and public shares
        let mut public_shares = Vec::new();
        for (idx, share_val) in [(1u32, share1), (2, share2), (3, share3)] {
            let pk_point = share_val * g;
            let statement = RepresentationStatement {
                generators: vec![g],
                target: pk_point,
            };
            let witness = RepresentationWitness {
                scalars: vec![share_val],
            };
            let mut t = Transcript::new(b"test-keygen");
            let proof =
                RepresentationProof::prove(&statement, &witness, &mut t, &mut rng).unwrap();
            public_shares.push(PublicKeyShare {
                index: TallierIndex(idx),
                point: pk_point,
                proof,
            });
        }

        // Encrypt message = 42
        let msg = Scalar::from(42u64);
        let r = Scalar::random(&mut rng);
        let ct = Ciphertext {
            d: r * g,
            e: r * election_key.0 + msg * h_i,
        };

        // Use talliers 1 and 3 (any 2-of-3 works)
        let key_shares = [
            KeyShare {
                index: TallierIndex(1),
                share: share1,
            },
            KeyShare {
                index: TallierIndex(3),
                share: share3,
            },
        ];

        let mut partials = Vec::new();
        let mut verify_transcripts = Vec::new();
        for ks in &key_shares {
            let pk_point = public_shares
                .iter()
                .find(|s| s.index == ks.index)
                .unwrap()
                .point;
            let mut t = Transcript::new(b"test-dec");
            let pd = PartialDecryption::create(ks, &ct, &g, &pk_point, &mut t, &mut rng).unwrap();
            partials.push(pd);
            verify_transcripts.push(Transcript::new(b"test-dec"));
        }

        let result = verify_and_decrypt(
            &ct,
            &partials,
            &public_shares,
            &g,
            &h_i,
            100,
            &mut verify_transcripts,
        )
        .unwrap();

        assert_eq!(result, 42);
    }

    #[test]
    fn solve_dlog_basic() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);

        // 0
        assert_eq!(
            solve_dlog(&RistrettoPoint::identity(), &g, 100),
            Some(0)
        );

        // small values
        for m in 1u64..20 {
            let target = Scalar::from(m) * g;
            assert_eq!(solve_dlog(&target, &g, 100), Some(m));
        }
    }

    #[test]
    fn solve_dlog_not_found() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let target = Scalar::from(50u64) * g;

        // Max value too low
        assert_eq!(solve_dlog(&target, &g, 10), None);
    }

    #[test]
    fn ciphertext_homomorphic_addition() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let h_i = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let pk = ElectionPublicKey(sk * g);

        let msg1 = Scalar::from(3u64);
        let msg2 = Scalar::from(5u64);

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);

        let ct1 = Ciphertext {
            d: r1 * g,
            e: r1 * pk.0 + msg1 * h_i,
        };
        let ct2 = Ciphertext {
            d: r2 * g,
            e: r2 * pk.0 + msg2 * h_i,
        };

        let ct_sum = ct1 + ct2;

        // Decrypt the sum with threshold-1
        let key_share = KeyShare {
            index: TallierIndex(1),
            share: sk,
        };

        let statement = RepresentationStatement {
            generators: vec![g],
            target: sk * g,
        };
        let witness = RepresentationWitness {
            scalars: vec![sk],
        };
        let mut t = Transcript::new(b"keygen");
        let proof = RepresentationProof::prove(&statement, &witness, &mut t, &mut rng).unwrap();

        let public_share = PublicKeyShare {
            index: TallierIndex(1),
            point: sk * g,
            proof,
        };

        let mut pd_t = Transcript::new(b"dec");
        let partial = PartialDecryption::create(
            &key_share,
            &ct_sum,
            &g,
            &public_share.point,
            &mut pd_t,
            &mut rng,
        )
        .unwrap();

        let mut vt = vec![Transcript::new(b"dec")];
        let result = verify_and_decrypt(
            &ct_sum,
            &[partial],
            &[public_share],
            &g,
            &h_i,
            100,
            &mut vt,
        )
        .unwrap();

        assert_eq!(result, 8); // 3 + 5
    }
}
