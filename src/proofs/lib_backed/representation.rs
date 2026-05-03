//! Library-backed generalized Schnorr representation proof via [`zkp`].
//!
//! Statement: `Y = Σ y_i · G_i`, knowledge of the `y_i`.
//!
//! Stack: `zkp` 0.8 + `curve25519-dalek-ng` 3 + `merlin` 2. Aura's home stack
//! is `curve25519-dalek` 4.1 + `merlin` 3, so we bridge at the module
//! boundary by canonical-byte roundtripping `Scalar` and `RistrettoPoint`,
//! and we re-key the zkp transcript with a 64-byte challenge squeezed from
//! the caller's merlin-3 transcript so the proof binds to Aura's protocol
//! context (election ID, prior framing, etc.).

use curve25519_dalek::ristretto::RistrettoPoint;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use zkp::toolbox::{prover::Prover, verifier::Verifier, SchnorrCS};
use zkp::{CompactProof, Transcript as ZkpTranscript};

use crate::errors::{AuraError, AuraResult};
use crate::transcript::TranscriptProtocol;

use super::bridge::dalek_ng;

// Re-export the hand-rolled statement/witness so call sites stay identical.
pub use crate::proofs::representation::{RepresentationStatement, RepresentationWitness};

const PROOF_TYPE: &str = "representation";
const ZKP_PROOF_LABEL: &[u8] = b"aura/lib-rep/zkp/v1";
const AURA_DOMAIN: &[u8] = b"aura/lib-rep/zkp/aura-bind/v1";

/// Static labels for the up-to-`MAX_GENERATORS` point slots, since `zkp::Prover`
/// requires `&'static [u8]` labels for variables.
const MAX_GENERATORS: usize = 16;
const GEN_LABELS: [&[u8]; MAX_GENERATORS] = [
    b"G_0", b"G_1", b"G_2", b"G_3", b"G_4", b"G_5", b"G_6", b"G_7", b"G_8", b"G_9", b"G_10",
    b"G_11", b"G_12", b"G_13", b"G_14", b"G_15",
];
const SCALAR_LABELS: [&[u8]; MAX_GENERATORS] = [
    b"y_0", b"y_1", b"y_2", b"y_3", b"y_4", b"y_5", b"y_6", b"y_7", b"y_8", b"y_9", b"y_10",
    b"y_11", b"y_12", b"y_13", b"y_14", b"y_15",
];
const TARGET_LABEL: &[u8] = b"Y";

/// A library-backed representation proof. Internally a `zkp::CompactProof`
/// (a Fiat-Shamir-derived challenge plus per-secret responses).
#[derive(Clone)]
pub struct RepresentationProof {
    pub inner: CompactProof,
}

impl core::fmt::Debug for RepresentationProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RepresentationProof")
            .field("responses_len", &self.inner.responses.len())
            .finish()
    }
}

/// Squeeze a 64-byte challenge from the caller-supplied Aura merlin-3
/// transcript and use it to label a fresh zkp merlin-2 transcript. This
/// transports Aura's protocol context (election ID, prior bindings) into
/// the zkp Fiat-Shamir without leaking incompatible transcript types.
fn rekey_zkp_transcript(aura_transcript: &mut Transcript) -> ZkpTranscript {
    aura_transcript.domain_sep(AURA_DOMAIN);
    let mut bind = [0u8; 64];
    aura_transcript.challenge_bytes(b"aura-bind", &mut bind);
    let mut zt = ZkpTranscript::new(b"aura-lib-backed");
    zt.append_message(b"aura-bind", &bind);
    zt
}

impl RepresentationProof {
    pub fn prove(
        statement: &RepresentationStatement,
        witness: &RepresentationWitness,
        transcript: &mut Transcript,
        _rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let n = statement.generators.len();
        if witness.scalars.len() != n {
            return Err(AuraError::InvalidParameter {
                reason: "witness length must match generators length".into(),
            });
        }
        if n > MAX_GENERATORS {
            return Err(AuraError::InvalidParameter {
                reason: format!("lib-backed representation proof supports at most {MAX_GENERATORS} generators"),
            });
        }

        let mut zt = rekey_zkp_transcript(transcript);
        let mut prover = Prover::new(ZKP_PROOF_LABEL, &mut zt);

        // Bridge witnesses (dalek 4 → dalek-ng 3) and allocate as scalars.
        let mut scalar_vars = Vec::with_capacity(n);
        for (i, y) in witness.scalars.iter().enumerate() {
            let y_ng = dalek_ng::scalar_from_bytes(&y.to_bytes(), PROOF_TYPE)?;
            scalar_vars.push(prover.allocate_scalar(SCALAR_LABELS[i], y_ng));
        }

        // Bridge generators and allocate as points.
        let mut gen_vars = Vec::with_capacity(n);
        for (i, g) in statement.generators.iter().enumerate() {
            let g_ng = dalek_ng::point_from_bytes(&g.compress().to_bytes(), PROOF_TYPE)?;
            let (var, _compressed) = prover.allocate_point(GEN_LABELS[i], g_ng);
            gen_vars.push(var);
        }

        // Bridge target and allocate.
        let target_ng =
            dalek_ng::point_from_bytes(&statement.target.compress().to_bytes(), PROOF_TYPE)?;
        let (target_var, _) = prover.allocate_point(TARGET_LABEL, target_ng);

        // Constraint: Y = Σ y_i · G_i
        let lc: Vec<_> = scalar_vars
            .iter()
            .copied()
            .zip(gen_vars.iter().copied())
            .collect();
        prover.constrain(target_var, lc);

        Ok(RepresentationProof {
            inner: prover.prove_compact(),
        })
    }

    pub fn verify(
        &self,
        statement: &RepresentationStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let n = statement.generators.len();
        if n > MAX_GENERATORS {
            return Err(AuraError::VerificationFailed {
                proof_type: "representation",
            });
        }

        let mut zt = rekey_zkp_transcript(transcript);
        let mut verifier = Verifier::new(ZKP_PROOF_LABEL, &mut zt);

        let mut scalar_vars = Vec::with_capacity(n);
        for i in 0..n {
            scalar_vars.push(verifier.allocate_scalar(SCALAR_LABELS[i]));
        }

        let mut gen_vars = Vec::with_capacity(n);
        for (i, g) in statement.generators.iter().enumerate() {
            let g_ng_compressed = compress_via_bridge(g)?;
            let var = verifier
                .allocate_point(GEN_LABELS[i], g_ng_compressed)
                .map_err(|_| AuraError::VerificationFailed {
                    proof_type: "representation",
                })?;
            gen_vars.push(var);
        }

        let target_ng_compressed = compress_via_bridge(&statement.target)?;
        let target_var = verifier
            .allocate_point(TARGET_LABEL, target_ng_compressed)
            .map_err(|_| AuraError::VerificationFailed {
                proof_type: "representation",
            })?;

        let lc: Vec<_> = scalar_vars
            .iter()
            .copied()
            .zip(gen_vars.iter().copied())
            .collect();
        verifier.constrain(target_var, lc);

        verifier
            .verify_compact(&self.inner)
            .map_err(|_| AuraError::VerificationFailed {
                proof_type: "representation",
            })
    }

    /// Sequential batch verify. The hand-rolled implementation uses random
    /// linear combinations across all proofs; `zkp` does not expose a
    /// cross-proof batcher, so we fall back to per-proof verification.
    pub fn batch_verify(
        proofs: &[RepresentationProof],
        statements: &[RepresentationStatement],
        transcripts: &mut [Transcript],
        _rng: &mut impl CryptoRngCore,
    ) -> AuraResult<()> {
        if proofs.len() != statements.len() || proofs.len() != transcripts.len() {
            return Err(AuraError::InvalidParameter {
                reason: "mismatched lengths in batch verify".into(),
            });
        }
        for ((proof, statement), transcript) in proofs
            .iter()
            .zip(statements.iter())
            .zip(transcripts.iter_mut())
        {
            proof
                .verify(statement, transcript)
                .map_err(|_| AuraError::BatchVerificationFailed { count: proofs.len() })?;
        }
        Ok(())
    }
}

/// Convert an Aura RistrettoPoint into a dalek-ng `CompressedRistretto` (the
/// type expected by zkp's verifier API). Goes through canonical 32 bytes.
fn compress_via_bridge(
    p: &RistrettoPoint,
) -> AuraResult<curve25519_dalek_ng::ristretto::CompressedRistretto> {
    let bytes = p.compress().to_bytes();
    Ok(curve25519_dalek_ng::ristretto::CompressedRistretto::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::scalar::Scalar;
    use curve25519_dalek::traits::MultiscalarMul;
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

        let mut pt = Transcript::new(b"test-rep-lib");
        let proof =
            RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-rep-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = OsRng;
        let (statement, mut witness) = random_statement_and_witness(3, &mut rng);
        witness.scalars[0] += Scalar::ONE;

        let mut pt = Transcript::new(b"test-rep-lib");
        let proof =
            RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-rep-lib");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn single_generator() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(1, &mut rng);

        let mut pt = Transcript::new(b"test-rep-lib");
        let proof =
            RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-rep-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn batch_verify_succeeds() {
        let mut rng = OsRng;
        let count = 5;

        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        let mut verify_transcripts = Vec::new();

        for _ in 0..count {
            let (statement, witness) = random_statement_and_witness(2, &mut rng);
            let mut pt = Transcript::new(b"test-batch-rep-lib");
            let proof =
                RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
            verify_transcripts.push(Transcript::new(b"test-batch-rep-lib"));
        }

        RepresentationProof::batch_verify(
            &proofs,
            &statements,
            &mut verify_transcripts,
            &mut rng,
        )
        .unwrap();
    }
}
