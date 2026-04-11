//! Serial validity proof.
//!
//! Proves: `C' = s*G + r'*H`, `D' = r''*G`, `E' = s*F + r''*Y`.
//! This binds the ballot serial number to the voter's identity commitment.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::errors::{AuraError, AuraResult};
use crate::transcript::{TranscriptProtocol, DOMAIN_SER_VAL_PROOF};

/// Public statement for a serial validity proof.
#[derive(Debug, Clone)]
pub struct SerValStatement {
    /// Serial number generator `F`.
    pub f: RistrettoPoint,
    /// Base generator `G`.
    pub g: RistrettoPoint,
    /// Blinding generator `H`.
    pub h: RistrettoPoint,
    /// Election public key `Y`.
    pub y: RistrettoPoint,
    /// Serial offset commitment `C' = s*G + r'*H`.
    pub c_prime: RistrettoPoint,
    /// Encrypted serial D component `D' = r''*G`.
    pub d_prime: RistrettoPoint,
    /// Encrypted serial E component `E' = s*F + r''*Y`.
    pub e_prime: RistrettoPoint,
}

/// Private witness: `(s, r', r'')`.
pub struct SerValWitness {
    pub s: Scalar,
    pub r_prime: Scalar,
    pub r_double_prime: Scalar,
}

impl Drop for SerValWitness {
    fn drop(&mut self) {
        self.s.zeroize();
        self.r_prime.zeroize();
        self.r_double_prime.zeroize();
    }
}

/// Proof of serial number validity.
#[derive(Debug, Clone)]
pub struct SerialValidityProof {
    /// Commitment for C' equation: `k_s * G + k_r' * H`.
    pub commitment_c: CompressedRistretto,
    /// Commitment for D' equation: `k_r'' * G`.
    pub commitment_d: CompressedRistretto,
    /// Commitment for E' equation: `k_s * F + k_r'' * Y`.
    pub commitment_e: CompressedRistretto,
    /// Response for s: `s_s = k_s + c * s`.
    pub response_s: Scalar,
    /// Response for r': `s_r' = k_r' + c * r'`.
    pub response_r_prime: Scalar,
    /// Response for r'': `s_r'' = k_r'' + c * r''`.
    pub response_r_double_prime: Scalar,
}

impl SerialValidityProof {
    pub fn prove(
        statement: &SerValStatement,
        witness: &SerValWitness,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        transcript.domain_sep(DOMAIN_SER_VAL_PROOF);
        transcript.append_point(b"F", &statement.f.compress());
        transcript.append_point(b"G", &statement.g.compress());
        transcript.append_point(b"H", &statement.h.compress());
        transcript.append_point(b"Y", &statement.y.compress());
        transcript.append_point(b"C'", &statement.c_prime.compress());
        transcript.append_point(b"D'", &statement.d_prime.compress());
        transcript.append_point(b"E'", &statement.e_prime.compress());

        // Sample nonces
        let k_s = Scalar::random(rng);
        let k_r_prime = Scalar::random(rng);
        let k_r_double_prime = Scalar::random(rng);

        // Commitments for three equations (sharing k_s and k_r'')
        let r_c = k_s * statement.g + k_r_prime * statement.h;
        let r_d = k_r_double_prime * statement.g;
        let r_e = k_s * statement.f + k_r_double_prime * statement.y;

        let r_c_compressed = r_c.compress();
        let r_d_compressed = r_d.compress();
        let r_e_compressed = r_e.compress();

        transcript.append_point(b"R_C", &r_c_compressed);
        transcript.append_point(b"R_D", &r_d_compressed);
        transcript.append_point(b"R_E", &r_e_compressed);
        let challenge = transcript.challenge_scalar(b"c");

        let s_s = k_s + challenge * witness.s;
        let s_r_prime = k_r_prime + challenge * witness.r_prime;
        let s_r_double_prime = k_r_double_prime + challenge * witness.r_double_prime;

        Ok(SerialValidityProof {
            commitment_c: r_c_compressed,
            commitment_d: r_d_compressed,
            commitment_e: r_e_compressed,
            response_s: s_s,
            response_r_prime: s_r_prime,
            response_r_double_prime: s_r_double_prime,
        })
    }

    pub fn verify(
        &self,
        statement: &SerValStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        transcript.domain_sep(DOMAIN_SER_VAL_PROOF);
        transcript.append_point(b"F", &statement.f.compress());
        transcript.append_point(b"G", &statement.g.compress());
        transcript.append_point(b"H", &statement.h.compress());
        transcript.append_point(b"Y", &statement.y.compress());
        transcript.append_point(b"C'", &statement.c_prime.compress());
        transcript.append_point(b"D'", &statement.d_prime.compress());
        transcript.append_point(b"E'", &statement.e_prime.compress());
        transcript.append_point(b"R_C", &self.commitment_c);
        transcript.append_point(b"R_D", &self.commitment_d);
        transcript.append_point(b"R_E", &self.commitment_e);
        let challenge = transcript.challenge_scalar(b"c");

        let r_c = self.commitment_c.decompress().ok_or(AuraError::VerificationFailed {
            proof_type: "serial_validity",
        })?;
        let r_d = self.commitment_d.decompress().ok_or(AuraError::VerificationFailed {
            proof_type: "serial_validity",
        })?;
        let r_e = self.commitment_e.decompress().ok_or(AuraError::VerificationFailed {
            proof_type: "serial_validity",
        })?;

        // Check C': s_s * G + s_r' * H == R_C + c * C'
        let lhs_c = self.response_s * statement.g + self.response_r_prime * statement.h;
        let rhs_c = r_c + challenge * statement.c_prime;

        // Check D': s_r'' * G == R_D + c * D'
        let lhs_d = self.response_r_double_prime * statement.g;
        let rhs_d = r_d + challenge * statement.d_prime;

        // Check E': s_s * F + s_r'' * Y == R_E + c * E'
        let lhs_e = self.response_s * statement.f + self.response_r_double_prime * statement.y;
        let rhs_e = r_e + challenge * statement.e_prime;

        if lhs_c == rhs_c && lhs_d == rhs_d && lhs_e == rhs_e {
            Ok(())
        } else {
            Err(AuraError::VerificationFailed {
                proof_type: "serial_validity",
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
    ) -> (SerValStatement, SerValWitness) {
        let f = RistrettoPoint::random(rng);
        let g = RistrettoPoint::random(rng);
        let h = RistrettoPoint::random(rng);
        let sk = Scalar::random(rng);
        let y = sk * g;

        let s = Scalar::random(rng);
        let r_prime = Scalar::random(rng);
        let r_double_prime = Scalar::random(rng);

        let c_prime = s * g + r_prime * h;
        let d_prime = r_double_prime * g;
        let e_prime = s * f + r_double_prime * y;

        (
            SerValStatement {
                f, g, h, y, c_prime, d_prime, e_prime,
            },
            SerValWitness {
                s,
                r_prime,
                r_double_prime,
            },
        )
    }

    #[test]
    fn prove_and_verify() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(&mut rng);

        let mut pt = Transcript::new(b"test-serval");
        let proof = SerialValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-serval");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = OsRng;
        let (statement, _) = random_statement_and_witness(&mut rng);
        let bad = SerValWitness {
            s: Scalar::random(&mut rng),
            r_prime: Scalar::random(&mut rng),
            r_double_prime: Scalar::random(&mut rng),
        };

        let mut pt = Transcript::new(b"test-serval");
        let proof = SerialValidityProof::prove(&statement, &bad, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-serval");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(&mut rng);

        let mut pt = Transcript::new(b"test-serval");
        let mut proof =
            SerialValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        proof.response_s += Scalar::ONE;

        let mut vt = Transcript::new(b"test-serval");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }
}
