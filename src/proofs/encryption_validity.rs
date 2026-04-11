//! Encryption validity proof.
//!
//! Proves valid ElGamal encryption: `D = r*G` and `E = r*Y + m*H_i`.
//! This is a compound Schnorr proof sharing the nonce `r` across two equations.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::errors::{AuraError, AuraResult};
use crate::transcript::{TranscriptProtocol, DOMAIN_ENC_VAL_PROOF};

/// Public statement for an encryption validity proof.
#[derive(Debug, Clone)]
pub struct EncValStatement {
    /// Base generator `G`.
    pub g: RistrettoPoint,
    /// Election public key `Y`.
    pub y: RistrettoPoint,
    /// Message generator `H_i`.
    pub h_i: RistrettoPoint,
    /// First ciphertext component `D = r*G`.
    pub d: RistrettoPoint,
    /// Second ciphertext component `E = r*Y + m*H_i`.
    pub e: RistrettoPoint,
}

/// Private witness: `(r, m)` such that `D = r*G` and `E = r*Y + m*H_i`.
pub struct EncValWitness {
    pub r: Scalar,
    pub m: Scalar,
}

impl Drop for EncValWitness {
    fn drop(&mut self) {
        self.r.zeroize();
        self.m.zeroize();
    }
}

/// Proof of valid ElGamal encryption.
#[derive(Debug, Clone)]
pub struct EncryptionValidityProof {
    /// Commitment for D equation: `k_r * G`.
    pub commitment_d: CompressedRistretto,
    /// Commitment for E equation: `k_r * Y + k_m * H_i`.
    pub commitment_e: CompressedRistretto,
    /// Response for r: `s_r = k_r + c * r`.
    pub response_r: Scalar,
    /// Response for m: `s_m = k_m + c * m`.
    pub response_m: Scalar,
}

impl EncryptionValidityProof {
    pub fn prove(
        statement: &EncValStatement,
        witness: &EncValWitness,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        // Commit statement
        transcript.domain_sep(DOMAIN_ENC_VAL_PROOF);
        transcript.append_point(b"G", &statement.g.compress());
        transcript.append_point(b"Y", &statement.y.compress());
        transcript.append_point(b"H_i", &statement.h_i.compress());
        transcript.append_point(b"D", &statement.d.compress());
        transcript.append_point(b"E", &statement.e.compress());

        // Sample nonces
        let k_r = Scalar::random(rng);
        let k_m = Scalar::random(rng);

        // Commitments
        let r_d = k_r * statement.g;
        let r_e = k_r * statement.y + k_m * statement.h_i;
        let r_d_compressed = r_d.compress();
        let r_e_compressed = r_e.compress();

        // Challenge
        transcript.append_point(b"R_D", &r_d_compressed);
        transcript.append_point(b"R_E", &r_e_compressed);
        let challenge = transcript.challenge_scalar(b"c");

        // Responses
        let s_r = k_r + challenge * witness.r;
        let s_m = k_m + challenge * witness.m;

        Ok(EncryptionValidityProof {
            commitment_d: r_d_compressed,
            commitment_e: r_e_compressed,
            response_r: s_r,
            response_m: s_m,
        })
    }

    pub fn verify(
        &self,
        statement: &EncValStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        // Reconstruct transcript
        transcript.domain_sep(DOMAIN_ENC_VAL_PROOF);
        transcript.append_point(b"G", &statement.g.compress());
        transcript.append_point(b"Y", &statement.y.compress());
        transcript.append_point(b"H_i", &statement.h_i.compress());
        transcript.append_point(b"D", &statement.d.compress());
        transcript.append_point(b"E", &statement.e.compress());
        transcript.append_point(b"R_D", &self.commitment_d);
        transcript.append_point(b"R_E", &self.commitment_e);
        let challenge = transcript.challenge_scalar(b"c");

        let r_d = self
            .commitment_d
            .decompress()
            .ok_or(AuraError::VerificationFailed {
                proof_type: "encryption_validity",
            })?;
        let r_e = self
            .commitment_e
            .decompress()
            .ok_or(AuraError::VerificationFailed {
                proof_type: "encryption_validity",
            })?;

        // Check D: s_r * G == R_D + c * D
        let lhs_d = self.response_r * statement.g;
        let rhs_d = r_d + challenge * statement.d;

        // Check E: s_r * Y + s_m * H_i == R_E + c * E
        let lhs_e = self.response_r * statement.y + self.response_m * statement.h_i;
        let rhs_e = r_e + challenge * statement.e;

        if lhs_d == rhs_d && lhs_e == rhs_e {
            Ok(())
        } else {
            Err(AuraError::VerificationFailed {
                proof_type: "encryption_validity",
            })
        }
    }

    /// Batch verify multiple encryption validity proofs.
    pub fn batch_verify(
        proofs: &[EncryptionValidityProof],
        statements: &[EncValStatement],
        transcripts: &mut [Transcript],
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<()> {
        if proofs.len() != statements.len() || proofs.len() != transcripts.len() {
            return Err(AuraError::InvalidParameter {
                reason: "mismatched lengths".into(),
            });
        }
        if proofs.is_empty() {
            return Ok(());
        }

        let mut all_scalars = Vec::new();
        let mut all_points = Vec::new();

        for (i, ((proof, statement), transcript)) in proofs
            .iter()
            .zip(statements.iter())
            .zip(transcripts.iter_mut())
            .enumerate()
        {
            transcript.domain_sep(DOMAIN_ENC_VAL_PROOF);
            transcript.append_point(b"G", &statement.g.compress());
            transcript.append_point(b"Y", &statement.y.compress());
            transcript.append_point(b"H_i", &statement.h_i.compress());
            transcript.append_point(b"D", &statement.d.compress());
            transcript.append_point(b"E", &statement.e.compress());
            transcript.append_point(b"R_D", &proof.commitment_d);
            transcript.append_point(b"R_E", &proof.commitment_e);
            let challenge = transcript.challenge_scalar(b"c");

            let w1 = if i == 0 {
                Scalar::ONE
            } else {
                Scalar::random(rng)
            };
            let w2 = Scalar::random(rng);

            let r_d = proof
                .commitment_d
                .decompress()
                .ok_or(AuraError::BatchVerificationFailed {
                    count: proofs.len(),
                })?;
            let r_e = proof
                .commitment_e
                .decompress()
                .ok_or(AuraError::BatchVerificationFailed {
                    count: proofs.len(),
                })?;

            // Eq 1: w1 * (s_r * G - c * D - R_D) = 0
            all_scalars.push(w1 * proof.response_r);
            all_points.push(statement.g);
            all_scalars.push(-(w1 * challenge));
            all_points.push(statement.d);
            all_scalars.push(-w1);
            all_points.push(r_d);

            // Eq 2: w2 * (s_r * Y + s_m * H_i - c * E - R_E) = 0
            all_scalars.push(w2 * proof.response_r);
            all_points.push(statement.y);
            all_scalars.push(w2 * proof.response_m);
            all_points.push(statement.h_i);
            all_scalars.push(-(w2 * challenge));
            all_points.push(statement.e);
            all_scalars.push(-w2);
            all_points.push(r_e);
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
    use crate::elgamal::encrypt::encrypt;
    use crate::elgamal::keys::ElectionPublicKey;
    use rand::rngs::OsRng;

    fn random_enc_statement_and_witness(
        rng: &mut impl CryptoRngCore,
    ) -> (EncValStatement, EncValWitness) {
        let g = RistrettoPoint::random(rng);
        let h_i = RistrettoPoint::random(rng);
        let sk = Scalar::random(rng);
        let y = sk * g;
        let pk = ElectionPublicKey(y);
        let msg = Scalar::from(1u64);
        let (ct, r) = encrypt(&msg, &h_i, &g, &pk, rng);
        (
            EncValStatement {
                g,
                y,
                h_i,
                d: ct.d,
                e: ct.e,
            },
            EncValWitness { r, m: msg },
        )
    }

    #[test]
    fn prove_and_verify() {
        let mut rng = OsRng;
        let (statement, witness) = random_enc_statement_and_witness(&mut rng);

        let mut pt = Transcript::new(b"test-encval");
        let proof =
            EncryptionValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-encval");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = OsRng;
        let (statement, _) = random_enc_statement_and_witness(&mut rng);
        let bad_witness = EncValWitness {
            r: Scalar::random(&mut rng),
            m: Scalar::random(&mut rng),
        };

        let mut pt = Transcript::new(b"test-encval");
        let proof =
            EncryptionValidityProof::prove(&statement, &bad_witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-encval");
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
            let (statement, witness) = random_enc_statement_and_witness(&mut rng);
            let mut pt = Transcript::new(b"test-batch-encval");
            let proof =
                EncryptionValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
            verify_transcripts.push(Transcript::new(b"test-batch-encval"));
        }

        EncryptionValidityProof::batch_verify(
            &proofs,
            &statements,
            &mut verify_transcripts,
            &mut rng,
        )
        .unwrap();
    }
}
