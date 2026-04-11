//! Bit vector commitment proof (Appendix A of the paper).
//!
//! Proves that a Pedersen vector commitment `B = r*H + sum(b_i * G_i)`
//! has binary components (`b_i in {0,1}`) summing to `w`.
//!
//! Generalization of Bootle et al. (ESORICS 2015) to support arbitrary `w`.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{MultiscalarMul, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::CryptoRngCore;

use crate::errors::{AuraError, AuraResult};
use crate::transcript::{TranscriptProtocol, DOMAIN_BIT_VECTOR_PROOF};

/// Public statement for a bit vector commitment proof.
#[derive(Debug, Clone)]
pub struct BitVectorStatement {
    /// Component generators `G_0, ..., G_{k'-1}`.
    pub generators: Vec<RistrettoPoint>,
    /// Blinding generator `H` (this is Y, the election public key, per paper).
    pub h: RistrettoPoint,
    /// The commitment `B = r*H + sum(b_i * G_i)`.
    pub b: RistrettoPoint,
    /// Required sum of bits: `sum(b_i) = w`.
    pub w: u32,
}

/// Private witness for a bit vector commitment proof.
pub struct BitVectorWitness {
    /// The bit values `b_0, ..., b_{k'-1}`, each in `{0, 1}`.
    pub bits: Vec<Scalar>,
    /// The blinding factor `r`.
    pub blinding: Scalar,
}

/// Proof that a Pedersen vector commitment contains binary values summing to `w`.
#[derive(Debug, Clone)]
pub struct BitVectorProof {
    /// Commitment `A`.
    pub a: CompressedRistretto,
    /// Commitment `C`.
    pub c: CompressedRistretto,
    /// Commitment `D`.
    pub d: CompressedRistretto,
    /// Response scalars `f_1, ..., f_{k'-1}`. (`f_0` is derived by verifier.)
    pub f: Vec<Scalar>,
    /// Response `z_A = r*x + r_A`.
    pub z_a: Scalar,
    /// Response `z_C = r_C*x + r_D`.
    pub z_c: Scalar,
}

impl BitVectorProof {
    /// Create a bit vector commitment proof.
    ///
    /// Implements the interactive protocol from Appendix A, made non-interactive
    /// via the strong Fiat-Shamir transform (Merlin transcript).
    pub fn prove(
        statement: &BitVectorStatement,
        witness: &BitVectorWitness,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let k = statement.generators.len();
        if witness.bits.len() != k {
            return Err(AuraError::InvalidParameter {
                reason: "bits length must match generators".into(),
            });
        }

        // Commit statement to transcript
        transcript.domain_sep(DOMAIN_BIT_VECTOR_PROOF);
        for g in &statement.generators {
            transcript.append_point(b"G_i", &g.compress());
        }
        transcript.append_point(b"H", &statement.h.compress());
        transcript.append_point(b"B", &statement.b.compress());
        transcript.append_u64(b"w", statement.w as u64);

        // Step 1: Sample random values
        let r_a = Scalar::random(rng);
        let r_c = Scalar::random(rng);
        let r_d = Scalar::random(rng);

        // a_i for i in [1, k): random; a_0 = -sum(a_i for i in [1, k))
        let a_rest: Vec<Scalar> = (1..k).map(|_| Scalar::random(rng)).collect();
        let a_0 = -a_rest.iter().sum::<Scalar>();
        let mut a = Vec::with_capacity(k);
        a.push(a_0);
        a.extend_from_slice(&a_rest);

        // Step 2: Compute commitments A, C, D
        // A = r_A * H + sum(a_i * G_i)
        let mut a_scalars = vec![r_a];
        let mut a_points = vec![statement.h];
        for (ai, gi) in a.iter().zip(statement.generators.iter()) {
            a_scalars.push(*ai);
            a_points.push(*gi);
        }
        let big_a = RistrettoPoint::multiscalar_mul(&a_scalars, &a_points);

        // C = r_C * H + sum(a_i * (1 - 2*b_i) * G_i)
        let mut c_scalars = vec![r_c];
        let mut c_points = vec![statement.h];
        for (i, gi) in statement.generators.iter().enumerate() {
            let coeff = a[i] * (Scalar::ONE - Scalar::from(2u64) * witness.bits[i]);
            c_scalars.push(coeff);
            c_points.push(*gi);
        }
        let big_c = RistrettoPoint::multiscalar_mul(&c_scalars, &c_points);

        // D = r_D * H - sum(a_i^2 * G_i)
        // (Note: negative sign on a_i^2 terms, per Bootle et al.)
        let mut d_scalars = vec![r_d];
        let mut d_points = vec![statement.h];
        for (i, gi) in statement.generators.iter().enumerate() {
            d_scalars.push(-(a[i] * a[i]));
            d_points.push(*gi);
        }
        let big_d = RistrettoPoint::multiscalar_mul(&d_scalars, &d_points);

        let a_compressed = big_a.compress();
        let c_compressed = big_c.compress();
        let d_compressed = big_d.compress();

        // Step 3: Challenge
        transcript.append_point(b"A", &a_compressed);
        transcript.append_point(b"C", &c_compressed);
        transcript.append_point(b"D", &d_compressed);
        let x = transcript.challenge_scalar(b"x");

        // Step 4: Compute responses
        // f_i = b_i * x + a_i for i in [1, k) (f_0 derived by verifier)
        let f: Vec<Scalar> = (1..k)
            .map(|i| witness.bits[i] * x + a[i])
            .collect();

        let z_a = witness.blinding * x + r_a;
        let z_c = r_c * x + r_d;

        Ok(BitVectorProof {
            a: a_compressed,
            c: c_compressed,
            d: d_compressed,
            f,
            z_a,
            z_c,
        })
    }

    /// Verify a bit vector commitment proof.
    pub fn verify(
        &self,
        statement: &BitVectorStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let k = statement.generators.len();
        if self.f.len() != k - 1 {
            return Err(AuraError::VerificationFailed {
                proof_type: "bit_vector",
            });
        }

        // Reconstruct transcript
        transcript.domain_sep(DOMAIN_BIT_VECTOR_PROOF);
        for g in &statement.generators {
            transcript.append_point(b"G_i", &g.compress());
        }
        transcript.append_point(b"H", &statement.h.compress());
        transcript.append_point(b"B", &statement.b.compress());
        transcript.append_u64(b"w", statement.w as u64);
        transcript.append_point(b"A", &self.a);
        transcript.append_point(b"C", &self.c);
        transcript.append_point(b"D", &self.d);
        let x = transcript.challenge_scalar(b"x");

        let big_a = self.a.decompress().ok_or(AuraError::VerificationFailed {
            proof_type: "bit_vector",
        })?;
        let big_c = self.c.decompress().ok_or(AuraError::VerificationFailed {
            proof_type: "bit_vector",
        })?;
        let big_d = self.d.decompress().ok_or(AuraError::VerificationFailed {
            proof_type: "bit_vector",
        })?;

        // Derive f_0 = w*x - sum(f_i for i in [1, k))
        let f_sum: Scalar = self.f.iter().sum();
        let f_0 = Scalar::from(statement.w) * x - f_sum;

        // Full f vector
        let mut f_full = Vec::with_capacity(k);
        f_full.push(f_0);
        f_full.extend_from_slice(&self.f);

        // Check 1: A + x*B == z_A * H + sum(f_i * G_i)
        let lhs1 = big_a + x * statement.b;
        let mut rhs1_scalars = vec![self.z_a];
        let mut rhs1_points = vec![statement.h];
        for (fi, gi) in f_full.iter().zip(statement.generators.iter()) {
            rhs1_scalars.push(*fi);
            rhs1_points.push(*gi);
        }
        let rhs1 = RistrettoPoint::vartime_multiscalar_mul(&rhs1_scalars, &rhs1_points);

        if lhs1 != rhs1 {
            return Err(AuraError::VerificationFailed {
                proof_type: "bit_vector",
            });
        }

        // Check 2: x*C + D == z_C * H + sum(f_i * (x - f_i) * G_i)
        let lhs2 = x * big_c + big_d;
        let mut rhs2_scalars = vec![self.z_c];
        let mut rhs2_points = vec![statement.h];
        for (fi, gi) in f_full.iter().zip(statement.generators.iter()) {
            rhs2_scalars.push(*fi * (x - fi));
            rhs2_points.push(*gi);
        }
        let rhs2 = RistrettoPoint::vartime_multiscalar_mul(&rhs2_scalars, &rhs2_points);

        if lhs2 != rhs2 {
            return Err(AuraError::VerificationFailed {
                proof_type: "bit_vector",
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::MultiscalarMul;
    use rand::rngs::OsRng;

    fn create_valid_statement_and_witness(
        k: usize,
        w: u32,
        rng: &mut impl CryptoRngCore,
    ) -> (BitVectorStatement, BitVectorWitness) {
        let generators: Vec<RistrettoPoint> =
            (0..k).map(|_| RistrettoPoint::random(rng)).collect();
        let h = RistrettoPoint::random(rng);

        // Create binary vector with exactly w ones
        let mut bits = vec![Scalar::ZERO; k];
        for i in 0..w as usize {
            bits[i] = Scalar::ONE;
        }

        let blinding = Scalar::random(rng);

        // B = blinding * H + sum(bits[i] * G_i)
        let mut scalars = vec![blinding];
        let mut points = vec![h];
        for (bi, gi) in bits.iter().zip(generators.iter()) {
            scalars.push(*bi);
            points.push(*gi);
        }
        let b = RistrettoPoint::multiscalar_mul(&scalars, &points);

        (
            BitVectorStatement {
                generators,
                h,
                b,
                w,
            },
            BitVectorWitness { bits, blinding },
        )
    }

    #[test]
    fn prove_and_verify_w1() {
        let mut rng = OsRng;
        let (statement, witness) = create_valid_statement_and_witness(8, 1, &mut rng);

        let mut pt = Transcript::new(b"test-bitvec");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_w3() {
        let mut rng = OsRng;
        let (statement, witness) = create_valid_statement_and_witness(8, 3, &mut rng);

        let mut pt = Transcript::new(b"test-bitvec");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_sum_fails() {
        let mut rng = OsRng;
        // Create a valid witness with w=2 but claim w=3
        let (mut statement, witness) = create_valid_statement_and_witness(8, 2, &mut rng);
        statement.w = 3;

        let mut pt = Transcript::new(b"test-bitvec");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn non_binary_value_fails() {
        let mut rng = OsRng;
        let k = 4;
        let generators: Vec<RistrettoPoint> =
            (0..k).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let h = RistrettoPoint::random(&mut rng);

        // Non-binary: [2, 0, 0, 0] sums to 2 but has non-binary entry
        let bits = vec![Scalar::from(2u64), Scalar::ZERO, Scalar::ZERO, Scalar::ZERO];
        let blinding = Scalar::random(&mut rng);

        let mut scalars = vec![blinding];
        let mut points = vec![h];
        for (bi, gi) in bits.iter().zip(generators.iter()) {
            scalars.push(*bi);
            points.push(*gi);
        }
        let b = RistrettoPoint::multiscalar_mul(&scalars, &points);

        let statement = BitVectorStatement {
            generators,
            h,
            b,
            w: 2,
        };
        let witness = BitVectorWitness { bits, blinding };

        let mut pt = Transcript::new(b"test-bitvec");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (statement, witness) = create_valid_statement_and_witness(6, 2, &mut rng);

        let mut pt = Transcript::new(b"test-bitvec");
        let mut proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        proof.z_a += Scalar::ONE;

        let mut vt = Transcript::new(b"test-bitvec");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn large_k() {
        let mut rng = OsRng;
        let (statement, witness) = create_valid_statement_and_witness(32, 5, &mut rng);

        let mut pt = Transcript::new(b"test-bitvec");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec");
        proof.verify(&statement, &mut vt).unwrap();
    }
}
