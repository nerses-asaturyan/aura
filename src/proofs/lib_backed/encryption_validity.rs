//! Library-backed encryption-validity proof via [`zkp`].
//!
//! Statement: `D = r·G  ∧  E = r·Y + m·H_i` — compound Schnorr with shared
//! nonce `r` between the two equations, plus the message witness `m`.
//!
//! Stack: `zkp` 0.8 + `curve25519-dalek-ng` 3 + `merlin` 2. Bridged via
//! canonical 32-byte encoding from Aura's `curve25519-dalek` 4.1 stack.

use merlin::Transcript;
use rand_core::CryptoRngCore;

use zkp::toolbox::{prover::Prover, verifier::Verifier, SchnorrCS};
use zkp::{CompactProof, Transcript as ZkpTranscript};

use crate::errors::{AuraError, AuraResult};
use crate::transcript::TranscriptProtocol;

use super::bridge::dalek_ng;

pub use crate::proofs::encryption_validity::{EncValStatement, EncValWitness};

const PROOF_TYPE: &str = "encryption_validity";
const ZKP_PROOF_LABEL: &[u8] = b"aura/lib-encval/zkp/v1";
const AURA_DOMAIN: &[u8] = b"aura/lib-encval/zkp/aura-bind/v1";

#[derive(Clone)]
pub struct EncryptionValidityProof {
    pub inner: CompactProof,
}

impl core::fmt::Debug for EncryptionValidityProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptionValidityProof")
            .field("responses_len", &self.inner.responses.len())
            .finish()
    }
}

fn rekey_zkp_transcript(aura_transcript: &mut Transcript) -> ZkpTranscript {
    aura_transcript.domain_sep(AURA_DOMAIN);
    let mut bind = [0u8; 64];
    aura_transcript.challenge_bytes(b"aura-bind", &mut bind);
    let mut zt = ZkpTranscript::new(b"aura-lib-backed");
    zt.append_message(b"aura-bind", &bind);
    zt
}

impl EncryptionValidityProof {
    pub fn prove(
        statement: &EncValStatement,
        witness: &EncValWitness,
        transcript: &mut Transcript,
        _rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let r_ng = dalek_ng::scalar_from_bytes(&witness.r.to_bytes(), PROOF_TYPE)?;
        let m_ng = dalek_ng::scalar_from_bytes(&witness.m.to_bytes(), PROOF_TYPE)?;

        let g_ng = dalek_ng::point_from_bytes(&statement.g.compress().to_bytes(), PROOF_TYPE)?;
        let y_ng = dalek_ng::point_from_bytes(&statement.y.compress().to_bytes(), PROOF_TYPE)?;
        let h_ng = dalek_ng::point_from_bytes(&statement.h_i.compress().to_bytes(), PROOF_TYPE)?;
        let d_ng = dalek_ng::point_from_bytes(&statement.d.compress().to_bytes(), PROOF_TYPE)?;
        let e_ng = dalek_ng::point_from_bytes(&statement.e.compress().to_bytes(), PROOF_TYPE)?;

        let mut zt = rekey_zkp_transcript(transcript);
        let mut prover = Prover::new(ZKP_PROOF_LABEL, &mut zt);

        let var_r = prover.allocate_scalar(b"r", r_ng);
        let var_m = prover.allocate_scalar(b"m", m_ng);
        let (var_g, _) = prover.allocate_point(b"G", g_ng);
        let (var_y, _) = prover.allocate_point(b"Y", y_ng);
        let (var_h, _) = prover.allocate_point(b"H_i", h_ng);
        let (var_d, _) = prover.allocate_point(b"D", d_ng);
        let (var_e, _) = prover.allocate_point(b"E", e_ng);

        // D = r·G
        prover.constrain(var_d, vec![(var_r, var_g)]);
        // E = r·Y + m·H_i
        prover.constrain(var_e, vec![(var_r, var_y), (var_m, var_h)]);

        Ok(EncryptionValidityProof {
            inner: prover.prove_compact(),
        })
    }

    pub fn verify(
        &self,
        statement: &EncValStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let g_ng = compress_via_bridge(&statement.g)?;
        let y_ng = compress_via_bridge(&statement.y)?;
        let h_ng = compress_via_bridge(&statement.h_i)?;
        let d_ng = compress_via_bridge(&statement.d)?;
        let e_ng = compress_via_bridge(&statement.e)?;

        let mut zt = rekey_zkp_transcript(transcript);
        let mut verifier = Verifier::new(ZKP_PROOF_LABEL, &mut zt);

        let var_r = verifier.allocate_scalar(b"r");
        let var_m = verifier.allocate_scalar(b"m");
        let var_g = verifier
            .allocate_point(b"G", g_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "encryption_validity" })?;
        let var_y = verifier
            .allocate_point(b"Y", y_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "encryption_validity" })?;
        let var_h = verifier
            .allocate_point(b"H_i", h_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "encryption_validity" })?;
        let var_d = verifier
            .allocate_point(b"D", d_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "encryption_validity" })?;
        let var_e = verifier
            .allocate_point(b"E", e_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "encryption_validity" })?;

        verifier.constrain(var_d, vec![(var_r, var_g)]);
        verifier.constrain(var_e, vec![(var_r, var_y), (var_m, var_h)]);

        verifier
            .verify_compact(&self.inner)
            .map_err(|_| AuraError::VerificationFailed {
                proof_type: "encryption_validity",
            })
    }

    /// Sequential batch-verify (no random-linear-combination batcher in zkp).
    pub fn batch_verify(
        proofs: &[EncryptionValidityProof],
        statements: &[EncValStatement],
        transcripts: &mut [Transcript],
        _rng: &mut impl CryptoRngCore,
    ) -> AuraResult<()> {
        if proofs.len() != statements.len() || proofs.len() != transcripts.len() {
            return Err(AuraError::InvalidParameter {
                reason: "mismatched lengths".into(),
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

fn compress_via_bridge(
    p: &curve25519_dalek::ristretto::RistrettoPoint,
) -> AuraResult<curve25519_dalek_ng::ristretto::CompressedRistretto> {
    let bytes = p.compress().to_bytes();
    Ok(curve25519_dalek_ng::ristretto::CompressedRistretto::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::encrypt::encrypt;
    use crate::elgamal::keys::ElectionPublicKey;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
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

        let mut pt = Transcript::new(b"test-encval-lib");
        let proof =
            EncryptionValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-encval-lib");
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

        let mut pt = Transcript::new(b"test-encval-lib");
        let proof =
            EncryptionValidityProof::prove(&statement, &bad_witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-encval-lib");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn batch_verify_succeeds() {
        let mut rng = OsRng;
        let count = 5;

        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        let mut verify_transcripts = Vec::new();

        for _ in 0..count {
            let (statement, witness) = random_enc_statement_and_witness(&mut rng);
            let mut pt = Transcript::new(b"test-batch-encval-lib");
            let proof =
                EncryptionValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
            verify_transcripts.push(Transcript::new(b"test-batch-encval-lib"));
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
