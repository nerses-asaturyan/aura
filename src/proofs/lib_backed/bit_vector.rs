//! Library-backed bit-vector proof via `bulletproofs` R1CS.
//!
//! Predicate proved: there exist `b_0, ..., b_{k-1}` such that
//!   1. `b_i * (b_i - 1) = 0` for all i  (binary)
//!   2. `Σ b_i = w`                       (Hamming weight = w)
//!
//! Stack: `bulletproofs` 5.x git/main, `curve25519-dalek` 4.1, `merlin` 3.
//! Same dalek/merlin major as Aura, so no byte bridge is needed for this proof.
//!
//! Statement-fidelity caveat: bulletproofs commits each bit using its own
//! 2-generator Pedersen scheme (`PedersenGens::default()`), producing `k`
//! `CompressedRistretto` per-bit commitments stored alongside the R1CS proof.
//! The proof does **not** bind to Aura's vector commitment
//! `B = r·H + Σ b_i · G_i` from `BitVectorStatement` — that linkage would
//! require a separate Schnorr-style relation and is out of scope for this
//! library replacement. The thesis benchmark should disclose this:
//! library-backed proves the predicate, hand-rolled additionally binds to B.

use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use crate::errors::{AuraError, AuraResult};

// Re-export the Aura statement / witness types so call sites stay identical.
pub use crate::proofs::bit_vector::{BitVectorStatement, BitVectorWitness};

/// A library-backed bit-vector proof. Stores per-bit Pedersen commitments and
/// the bulletproofs R1CS proof of the binary + sum-to-w predicate.
#[derive(Debug, Clone)]
pub struct BitVectorProof {
    /// Per-bit Pedersen commitments `b_i * B + r_i * B_blinding` (bulletproofs
    /// `PedersenGens`), one per element of the vector.
    pub bit_commitments: Vec<CompressedRistretto>,
    /// Bulletproofs R1CS proof certifying each bit is binary and the sum equals
    /// `statement.w`.
    pub r1cs_proof: R1CSProof,
}

/// Add the bit-vector constraints to a constraint system.
///
/// `bits` are wires already in the CS (one per element of the vector).
fn enforce_bitvec_constraints<CS: ConstraintSystem>(cs: &mut CS, bits: &[Variable], w: u32) {
    // 1. Each bit is binary: b_i * (b_i - 1) = 0.
    for &b in bits {
        let (_, _, out) = cs.multiply(b.into(), b - Scalar::ONE);
        cs.constrain(out.into());
    }

    // 2. Sum of bits equals w.
    let sum_lc: LinearCombination = bits
        .iter()
        .map(|b| LinearCombination::from(*b))
        .fold(LinearCombination::default(), |acc, lc| acc + lc);
    cs.constrain(sum_lc - LinearCombination::from(Scalar::from(w as u64)));
}

/// Aura's transcript domain tag for this proof type, applied to the bulletproofs
/// transcript before the prover/verifier touch it. Ensures domain separation
/// between hand-rolled and library-backed paths.
const DOMAIN: &[u8] = b"aura/lib-bit-vector/bp-r1cs/v1";

impl BitVectorProof {
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

        // Bind statement context onto the transcript (matches verify).
        bind_statement(transcript, statement);

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(k.next_power_of_two().max(2), 1);

        let mut prover = Prover::new(&pc_gens, transcript);

        // Commit each bit with a fresh blinding factor; remember the
        // commitments so the verifier can re-bind them to the same wires.
        let mut commitments = Vec::with_capacity(k);
        let mut bit_vars = Vec::with_capacity(k);
        for bit in &witness.bits {
            let blinding = Scalar::random(rng);
            let (com, var) = prover.commit(*bit, blinding);
            commitments.push(com);
            bit_vars.push(var);
        }

        enforce_bitvec_constraints(&mut prover, &bit_vars, statement.w);

        let r1cs_proof = prover.prove(&bp_gens).map_err(|_| AuraError::VerificationFailed {
            proof_type: "bit_vector",
        })?;

        Ok(BitVectorProof {
            bit_commitments: commitments,
            r1cs_proof,
        })
    }

    pub fn verify(
        &self,
        statement: &BitVectorStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let k = statement.generators.len();
        if self.bit_commitments.len() != k {
            return Err(AuraError::VerificationFailed {
                proof_type: "bit_vector",
            });
        }

        bind_statement(transcript, statement);

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(k.next_power_of_two().max(2), 1);

        let mut verifier = Verifier::new(transcript);

        let bit_vars: Vec<Variable> = self
            .bit_commitments
            .iter()
            .map(|com| verifier.commit(*com))
            .collect();

        enforce_bitvec_constraints(&mut verifier, &bit_vars, statement.w);

        verifier
            .verify(&self.r1cs_proof, &pc_gens, &bp_gens)
            .map_err(|_| AuraError::VerificationFailed {
                proof_type: "bit_vector",
            })
    }
}

/// Append statement parameters to the transcript so prover and verifier
/// generate identical bulletproofs challenges. Mirrors the layout used by
/// the hand-rolled bit-vector proof, with a distinct domain tag.
fn bind_statement(transcript: &mut Transcript, statement: &BitVectorStatement) {
    transcript.append_message(b"dom-sep", DOMAIN);
    for g in &statement.generators {
        transcript.append_message(b"G_i", g.compress().as_bytes());
    }
    transcript.append_message(b"H", statement.h.compress().as_bytes());
    transcript.append_message(b"B", statement.b.compress().as_bytes());
    transcript.append_message(b"w", &(statement.w as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
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

        let mut bits = vec![Scalar::ZERO; k];
        for i in 0..w as usize {
            bits[i] = Scalar::ONE;
        }

        let blinding = Scalar::random(rng);

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

        let mut pt = Transcript::new(b"test-bitvec-lib");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_w3() {
        let mut rng = OsRng;
        let (statement, witness) = create_valid_statement_and_witness(8, 3, &mut rng);

        let mut pt = Transcript::new(b"test-bitvec-lib");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_sum_fails() {
        let mut rng = OsRng;
        let (mut statement, witness) = create_valid_statement_and_witness(8, 2, &mut rng);
        statement.w = 3; // claim wrong sum

        let mut pt = Transcript::new(b"test-bitvec-lib");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec-lib");
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

        let mut pt = Transcript::new(b"test-bitvec-lib");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec-lib");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn large_k() {
        let mut rng = OsRng;
        let (statement, witness) = create_valid_statement_and_witness(32, 5, &mut rng);

        let mut pt = Transcript::new(b"test-bitvec-lib");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-bitvec-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }
}
