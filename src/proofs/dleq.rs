//! Chaum-Pedersen discrete log equality (DLEQ) proof.
//!
//! Proves that two group elements `Y = yG` and `Y' = yH` share
//! the same discrete logarithm `y` with respect to generators `G` and `H`.
//!
//! Used by ElGamal partial decryption to prove correct key share usage.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::errors::{AuraError, AuraResult};
use crate::transcript::{TranscriptProtocol, DOMAIN_DLEQ_PROOF};

/// Public statement for a DLEQ proof.
#[derive(Debug, Clone)]
pub struct DleqStatement {
    /// First base generator `G`.
    pub g: RistrettoPoint,
    /// Second base generator `H`.
    pub h: RistrettoPoint,
    /// `Y = y * G`.
    pub y: RistrettoPoint,
    /// `Y' = y * H`.
    pub y_prime: RistrettoPoint,
}

/// Private witness for a DLEQ proof.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DleqWitness {
    /// The shared discrete logarithm `y`.
    pub scalar: Scalar,
}

/// A DLEQ proof: proves `Y = yG` and `Y' = yH` for the same `y`.
#[derive(Debug, Clone)]
pub struct DleqProof {
    /// Commitment on first base: `k * G`.
    pub commitment_g: CompressedRistretto,
    /// Commitment on second base: `k * H`.
    pub commitment_h: CompressedRistretto,
    /// Response: `s = k + c * y`.
    pub response: Scalar,
}

impl DleqProof {
    /// Create a DLEQ proof.
    pub fn prove(
        statement: &DleqStatement,
        witness: &DleqWitness,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        // Commit statement to transcript
        transcript.domain_sep(DOMAIN_DLEQ_PROOF);
        transcript.append_point(b"G", &statement.g.compress());
        transcript.append_point(b"H", &statement.h.compress());
        transcript.append_point(b"Y", &statement.y.compress());
        transcript.append_point(b"Y'", &statement.y_prime.compress());

        // Sample nonce and compute commitments
        let k = Scalar::random(rng);
        let r_g = k * statement.g;
        let r_h = k * statement.h;
        let r_g_compressed = r_g.compress();
        let r_h_compressed = r_h.compress();

        // Challenge
        transcript.append_point(b"R_G", &r_g_compressed);
        transcript.append_point(b"R_H", &r_h_compressed);
        let challenge = transcript.challenge_scalar(b"c");

        // Response: s = k + c * y
        let response = k + challenge * witness.scalar;

        Ok(DleqProof {
            commitment_g: r_g_compressed,
            commitment_h: r_h_compressed,
            response,
        })
    }

    /// Verify a DLEQ proof.
    pub fn verify(
        &self,
        statement: &DleqStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        // Reconstruct transcript
        transcript.domain_sep(DOMAIN_DLEQ_PROOF);
        transcript.append_point(b"G", &statement.g.compress());
        transcript.append_point(b"H", &statement.h.compress());
        transcript.append_point(b"Y", &statement.y.compress());
        transcript.append_point(b"Y'", &statement.y_prime.compress());
        transcript.append_point(b"R_G", &self.commitment_g);
        transcript.append_point(b"R_H", &self.commitment_h);

        let challenge = transcript.challenge_scalar(b"c");

        let r_g = self
            .commitment_g
            .decompress()
            .ok_or(AuraError::VerificationFailed { proof_type: "dleq" })?;
        let r_h = self
            .commitment_h
            .decompress()
            .ok_or(AuraError::VerificationFailed { proof_type: "dleq" })?;

        // Check: s * G == R_G + c * Y
        let lhs_g = self.response * statement.g;
        let rhs_g = r_g + challenge * statement.y;

        // Check: s * H == R_H + c * Y'
        let lhs_h = self.response * statement.h;
        let rhs_h = r_h + challenge * statement.y_prime;

        if lhs_g == rhs_g && lhs_h == rhs_h {
            Ok(())
        } else {
            Err(AuraError::VerificationFailed { proof_type: "dleq" })
        }
    }

    /// Batch verify multiple DLEQ proofs.
    pub fn batch_verify(
        proofs: &[DleqProof],
        statements: &[DleqStatement],
        transcripts: &mut [Transcript],
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<()> {
        if proofs.len() != statements.len() || proofs.len() != transcripts.len() {
            return Err(AuraError::InvalidParameter {
                reason: "mismatched lengths in batch verify".into(),
            });
        }
        if proofs.is_empty() {
            return Ok(());
        }

        // For each proof i, we have two equations:
        //   s_i * G_i - c_i * Y_i - R_{G,i} == 0
        //   s_i * H_i - c_i * Y'_i - R_{H,i} == 0
        //
        // With weights w_i:
        //   sum_i w_i * (s_i * G_i - c_i * Y_i - R_{G,i} + w'_i * (s_i * H_i - c_i * Y'_i - R_{H,i})) == 0
        // We use two independent weights per proof for the two equations.

        let mut all_scalars = Vec::new();
        let mut all_points = Vec::new();

        for (i, ((proof, statement), transcript)) in proofs
            .iter()
            .zip(statements.iter())
            .zip(transcripts.iter_mut())
            .enumerate()
        {
            // Reconstruct challenge
            transcript.domain_sep(DOMAIN_DLEQ_PROOF);
            transcript.append_point(b"G", &statement.g.compress());
            transcript.append_point(b"H", &statement.h.compress());
            transcript.append_point(b"Y", &statement.y.compress());
            transcript.append_point(b"Y'", &statement.y_prime.compress());
            transcript.append_point(b"R_G", &proof.commitment_g);
            transcript.append_point(b"R_H", &proof.commitment_h);
            let challenge = transcript.challenge_scalar(b"c");

            let w1 = if i == 0 {
                Scalar::ONE
            } else {
                Scalar::random(rng)
            };
            let w2 = Scalar::random(rng);

            let r_g = proof
                .commitment_g
                .decompress()
                .ok_or(AuraError::BatchVerificationFailed {
                    count: proofs.len(),
                })?;
            let r_h = proof
                .commitment_h
                .decompress()
                .ok_or(AuraError::BatchVerificationFailed {
                    count: proofs.len(),
                })?;

            // Equation 1: w1 * (s * G - c * Y - R_G)
            all_scalars.push(w1 * proof.response);
            all_points.push(statement.g);
            all_scalars.push(-(w1 * challenge));
            all_points.push(statement.y);
            all_scalars.push(-w1);
            all_points.push(r_g);

            // Equation 2: w2 * (s * H - c * Y' - R_H)
            all_scalars.push(w2 * proof.response);
            all_points.push(statement.h);
            all_scalars.push(-(w2 * challenge));
            all_points.push(statement.y_prime);
            all_scalars.push(-w2);
            all_points.push(r_h);
        }

        let result = RistrettoPoint::vartime_multiscalar_mul(&all_scalars, &all_points);

        use curve25519_dalek::traits::Identity;
        if result == RistrettoPoint::identity() {
            Ok(())
        } else {
            Err(AuraError::BatchVerificationFailed {
                count: proofs.len(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_statement_and_witness(
        rng: &mut impl CryptoRngCore,
    ) -> (DleqStatement, DleqWitness) {
        let g = RistrettoPoint::random(rng);
        let h = RistrettoPoint::random(rng);
        let y_scalar = Scalar::random(rng);
        let y = y_scalar * g;
        let y_prime = y_scalar * h;
        (
            DleqStatement { g, h, y, y_prime },
            DleqWitness { scalar: y_scalar },
        )
    }

    #[test]
    fn prove_and_verify() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(&mut rng);

        let mut pt = Transcript::new(b"test-dleq");
        let proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-dleq");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = OsRng;
        let (statement, _) = random_statement_and_witness(&mut rng);
        let bad_witness = DleqWitness {
            scalar: Scalar::random(&mut rng),
        };

        let mut pt = Transcript::new(b"test-dleq");
        let proof = DleqProof::prove(&statement, &bad_witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-dleq");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(&mut rng);

        let mut pt = Transcript::new(b"test-dleq");
        let mut proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        proof.response += Scalar::ONE;

        let mut vt = Transcript::new(b"test-dleq");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn mismatched_dlog_fails() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);
        let y1 = Scalar::random(&mut rng);
        let y2 = Scalar::random(&mut rng);

        let statement = DleqStatement {
            g,
            h,
            y: y1 * g,
            y_prime: y2 * h, // different dlog!
        };
        let witness = DleqWitness { scalar: y1 };

        let mut pt = Transcript::new(b"test-dleq");
        let proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-dleq");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn batch_verify_succeeds() {
        let mut rng = OsRng;
        let count = 10;

        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        let mut verify_transcripts = Vec::new();

        for _ in 0..count {
            let (statement, witness) = random_statement_and_witness(&mut rng);
            let mut pt = Transcript::new(b"test-batch-dleq");
            let proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
            verify_transcripts.push(Transcript::new(b"test-batch-dleq"));
        }

        DleqProof::batch_verify(&proofs, &statements, &mut verify_transcripts, &mut rng).unwrap();
    }

    #[test]
    fn batch_verify_detects_bad_proof() {
        let mut rng = OsRng;
        let count = 5;

        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        let mut verify_transcripts = Vec::new();

        for _ in 0..count {
            let (statement, witness) = random_statement_and_witness(&mut rng);
            let mut pt = Transcript::new(b"test-batch-dleq");
            let proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
            verify_transcripts.push(Transcript::new(b"test-batch-dleq"));
        }

        proofs[2].response += Scalar::ONE;

        assert!(
            DleqProof::batch_verify(&proofs, &statements, &mut verify_transcripts, &mut rng)
                .is_err()
        );
    }
}
