//! Generalized Schnorr representation proof.
//!
//! Proves knowledge of scalars `{y_i}` such that `Y = sum(y_i * G_i)`.
//!
//! This is the building block used by DKG key verification and voter setup.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::errors::{AuraError, AuraResult};
use crate::transcript::{TranscriptProtocol, DOMAIN_REP_PROOF};

/// Public statement for a representation proof.
#[derive(Debug, Clone)]
pub struct RepresentationStatement {
    /// Generators `G_0, ..., G_{n-1}`.
    pub generators: Vec<RistrettoPoint>,
    /// Target point `Y = sum(y_i * G_i)`.
    pub target: RistrettoPoint,
}

/// Private witness for a representation proof.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RepresentationWitness {
    /// Scalars `y_0, ..., y_{n-1}` such that `Y = sum(y_i * G_i)`.
    pub scalars: Vec<Scalar>,
}

/// A representation proof: proves knowledge of `{y_i}` such that `Y = sum(y_i * G_i)`.
#[derive(Debug, Clone)]
pub struct RepresentationProof {
    /// Commitment `R = sum(k_i * G_i)` where `k_i` are nonces.
    pub commitment: CompressedRistretto,
    /// Responses `s_i = k_i + c * y_i` for each generator.
    pub responses: Vec<Scalar>,
}

impl RepresentationProof {
    /// Create a representation proof.
    pub fn prove(
        statement: &RepresentationStatement,
        witness: &RepresentationWitness,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let n = statement.generators.len();
        if witness.scalars.len() != n {
            return Err(AuraError::InvalidParameter {
                reason: "witness length must match generators length".into(),
            });
        }

        // Commit statement to transcript
        transcript.domain_sep(DOMAIN_REP_PROOF);
        for (i, g) in statement.generators.iter().enumerate() {
            transcript.append_point(b"G", &g.compress());
            transcript.append_u64(b"i", i as u64);
        }
        transcript.append_point(b"Y", &statement.target.compress());

        // Sample nonces and compute commitment
        let nonces: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        let commitment = RistrettoPoint::multiscalar_mul(&nonces, &statement.generators);
        let commitment_compressed = commitment.compress();

        // Challenge
        transcript.append_point(b"R", &commitment_compressed);
        let challenge = transcript.challenge_scalar(b"c");

        // Responses: s_i = k_i + c * y_i
        let responses: Vec<Scalar> = nonces
            .iter()
            .zip(witness.scalars.iter())
            .map(|(k, y)| k + challenge * y)
            .collect();

        Ok(RepresentationProof {
            commitment: commitment_compressed,
            responses,
        })
    }

    /// Verify a representation proof.
    pub fn verify(
        &self,
        statement: &RepresentationStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let n = statement.generators.len();
        if self.responses.len() != n {
            return Err(AuraError::VerificationFailed {
                proof_type: "representation",
            });
        }

        // Reconstruct transcript
        transcript.domain_sep(DOMAIN_REP_PROOF);
        for (i, g) in statement.generators.iter().enumerate() {
            transcript.append_point(b"G", &g.compress());
            transcript.append_u64(b"i", i as u64);
        }
        transcript.append_point(b"Y", &statement.target.compress());
        transcript.append_point(b"R", &self.commitment);

        let challenge = transcript.challenge_scalar(b"c");

        // Check: R == sum(s_i * G_i) - c * Y
        // Equivalently: sum(s_i * G_i) - c * Y - R == 0
        let commitment_point = self
            .commitment
            .decompress()
            .ok_or(AuraError::VerificationFailed {
                proof_type: "representation",
            })?;

        let lhs = RistrettoPoint::vartime_multiscalar_mul(&self.responses, &statement.generators);
        let rhs = commitment_point + challenge * statement.target;

        if lhs == rhs {
            Ok(())
        } else {
            Err(AuraError::VerificationFailed {
                proof_type: "representation",
            })
        }
    }

    /// Batch verify multiple representation proofs.
    ///
    /// Uses random linear combination to compress all verification equations
    /// into a single multi-scalar multiplication check.
    pub fn batch_verify(
        proofs: &[RepresentationProof],
        statements: &[RepresentationStatement],
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

        // For each proof i, verification equation is:
        //   sum(s_{i,j} * G_{i,j}) - c_i * Y_i - R_i == 0
        //
        // With random weight w_i:
        //   sum_i( w_i * sum_j(s_{i,j} * G_{i,j}) - w_i * c_i * Y_i - w_i * R_i ) == 0

        let mut all_scalars = Vec::new();
        let mut all_points = Vec::new();

        for (i, ((proof, statement), transcript)) in proofs
            .iter()
            .zip(statements.iter())
            .zip(transcripts.iter_mut())
            .enumerate()
        {
            if proof.responses.len() != statement.generators.len() {
                return Err(AuraError::BatchVerificationFailed { count: i + 1 });
            }

            // Reconstruct challenge
            transcript.domain_sep(DOMAIN_REP_PROOF);
            for (j, g) in statement.generators.iter().enumerate() {
                transcript.append_point(b"G", &g.compress());
                transcript.append_u64(b"i", j as u64);
            }
            transcript.append_point(b"Y", &statement.target.compress());
            transcript.append_point(b"R", &proof.commitment);
            let challenge = transcript.challenge_scalar(b"c");

            let weight = if i == 0 {
                Scalar::ONE
            } else {
                Scalar::random(rng)
            };

            // +w * s_{i,j} * G_{i,j}
            for (s, g) in proof.responses.iter().zip(statement.generators.iter()) {
                all_scalars.push(weight * s);
                all_points.push(*g);
            }

            // -w * c_i * Y_i
            all_scalars.push(-(weight * challenge));
            all_points.push(statement.target);

            // -w * R_i
            let r_point =
                proof
                    .commitment
                    .decompress()
                    .ok_or(AuraError::BatchVerificationFailed {
                        count: proofs.len(),
                    })?;
            all_scalars.push(-weight);
            all_points.push(r_point);
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
        n: usize,
        rng: &mut impl CryptoRngCore,
    ) -> (RepresentationStatement, RepresentationWitness) {
        let generators: Vec<RistrettoPoint> =
            (0..n).map(|_| RistrettoPoint::random(rng)).collect();
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        let target = RistrettoPoint::multiscalar_mul(&scalars, &generators);
        (
            RepresentationStatement { generators, target },
            RepresentationWitness { scalars },
        )
    }

    #[test]
    fn prove_and_verify() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(3, &mut rng);

        let mut pt = Transcript::new(b"test-rep");
        let proof =
            RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-rep");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = OsRng;
        let (statement, mut witness) = random_statement_and_witness(3, &mut rng);
        witness.scalars[0] += Scalar::ONE; // tamper

        let mut pt = Transcript::new(b"test-rep");
        let proof =
            RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-rep");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(2, &mut rng);

        let mut pt = Transcript::new(b"test-rep");
        let mut proof =
            RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        // Tamper with a response
        proof.responses[0] += Scalar::ONE;

        let mut vt = Transcript::new(b"test-rep");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn single_generator() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(1, &mut rng);

        let mut pt = Transcript::new(b"test-rep");
        let proof =
            RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-rep");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn batch_verify_succeeds() {
        let mut rng = OsRng;
        let count = 10;

        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        let mut verify_transcripts = Vec::new();

        for _ in 0..count {
            let (statement, witness) = random_statement_and_witness(3, &mut rng);
            let mut pt = Transcript::new(b"test-batch");
            let proof =
                RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
            verify_transcripts.push(Transcript::new(b"test-batch"));
        }

        RepresentationProof::batch_verify(
            &proofs,
            &statements,
            &mut verify_transcripts,
            &mut rng,
        )
        .unwrap();
    }

    #[test]
    fn batch_verify_detects_bad_proof() {
        let mut rng = OsRng;
        let count = 5;

        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        let mut verify_transcripts = Vec::new();

        for _ in 0..count {
            let (statement, witness) = random_statement_and_witness(3, &mut rng);
            let mut pt = Transcript::new(b"test-batch");
            let proof =
                RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
            verify_transcripts.push(Transcript::new(b"test-batch"));
        }

        // Tamper with one proof
        proofs[2].responses[0] += Scalar::ONE;

        assert!(RepresentationProof::batch_verify(
            &proofs,
            &statements,
            &mut verify_transcripts,
            &mut rng,
        )
        .is_err());
    }
}
