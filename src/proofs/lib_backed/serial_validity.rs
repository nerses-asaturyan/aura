//! Library-backed serial-validity proof via [`zkp`].
//!
//! Statement (3 coupled equations, 2 shared scalars):
//!   `C' = s·G + r'·H`
//!   `D' = r''·G`
//!   `E' = s·F + r''·Y`
//!
//! Stack: `zkp` 0.8 + `curve25519-dalek-ng` 3 + `merlin` 2. Bridged via
//! canonical 32-byte encoding from Aura's dalek-4 stack.

use merlin::Transcript;
use rand_core::CryptoRngCore;

use zkp::toolbox::{prover::Prover, verifier::Verifier, SchnorrCS};
use zkp::{CompactProof, Transcript as ZkpTranscript};

use crate::errors::{AuraError, AuraResult};
use crate::transcript::TranscriptProtocol;

use super::bridge::dalek_ng;

pub use crate::proofs::serial_validity::{SerValStatement, SerValWitness};

const PROOF_TYPE: &str = "serial_validity";
const ZKP_PROOF_LABEL: &[u8] = b"aura/lib-serval/zkp/v1";
const AURA_DOMAIN: &[u8] = b"aura/lib-serval/zkp/aura-bind/v1";

#[derive(Clone)]
pub struct SerialValidityProof {
    pub inner: CompactProof,
}

impl core::fmt::Debug for SerialValidityProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SerialValidityProof")
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

fn compress_via_bridge(
    p: &curve25519_dalek::ristretto::RistrettoPoint,
) -> AuraResult<curve25519_dalek_ng::ristretto::CompressedRistretto> {
    let bytes = p.compress().to_bytes();
    Ok(curve25519_dalek_ng::ristretto::CompressedRistretto::from_slice(&bytes))
}

impl SerialValidityProof {
    pub fn prove(
        statement: &SerValStatement,
        witness: &SerValWitness,
        transcript: &mut Transcript,
        _rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let s_ng = dalek_ng::scalar_from_bytes(&witness.s.to_bytes(), PROOF_TYPE)?;
        let rp_ng = dalek_ng::scalar_from_bytes(&witness.r_prime.to_bytes(), PROOF_TYPE)?;
        let rpp_ng =
            dalek_ng::scalar_from_bytes(&witness.r_double_prime.to_bytes(), PROOF_TYPE)?;

        let f_ng = dalek_ng::point_from_bytes(&statement.f.compress().to_bytes(), PROOF_TYPE)?;
        let g_ng = dalek_ng::point_from_bytes(&statement.g.compress().to_bytes(), PROOF_TYPE)?;
        let h_ng = dalek_ng::point_from_bytes(&statement.h.compress().to_bytes(), PROOF_TYPE)?;
        let y_ng = dalek_ng::point_from_bytes(&statement.y.compress().to_bytes(), PROOF_TYPE)?;
        let cp_ng =
            dalek_ng::point_from_bytes(&statement.c_prime.compress().to_bytes(), PROOF_TYPE)?;
        let dp_ng =
            dalek_ng::point_from_bytes(&statement.d_prime.compress().to_bytes(), PROOF_TYPE)?;
        let ep_ng =
            dalek_ng::point_from_bytes(&statement.e_prime.compress().to_bytes(), PROOF_TYPE)?;

        let mut zt = rekey_zkp_transcript(transcript);
        let mut prover = Prover::new(ZKP_PROOF_LABEL, &mut zt);

        let var_s = prover.allocate_scalar(b"s", s_ng);
        let var_rp = prover.allocate_scalar(b"r_prime", rp_ng);
        let var_rpp = prover.allocate_scalar(b"r_double_prime", rpp_ng);

        let (var_f, _) = prover.allocate_point(b"F", f_ng);
        let (var_g, _) = prover.allocate_point(b"G", g_ng);
        let (var_h, _) = prover.allocate_point(b"H", h_ng);
        let (var_y, _) = prover.allocate_point(b"Y", y_ng);
        let (var_cp, _) = prover.allocate_point(b"C_prime", cp_ng);
        let (var_dp, _) = prover.allocate_point(b"D_prime", dp_ng);
        let (var_ep, _) = prover.allocate_point(b"E_prime", ep_ng);

        // C' = s·G + r'·H
        prover.constrain(var_cp, vec![(var_s, var_g), (var_rp, var_h)]);
        // D' = r''·G
        prover.constrain(var_dp, vec![(var_rpp, var_g)]);
        // E' = s·F + r''·Y
        prover.constrain(var_ep, vec![(var_s, var_f), (var_rpp, var_y)]);

        Ok(SerialValidityProof {
            inner: prover.prove_compact(),
        })
    }

    pub fn verify(
        &self,
        statement: &SerValStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let f_ng = compress_via_bridge(&statement.f)?;
        let g_ng = compress_via_bridge(&statement.g)?;
        let h_ng = compress_via_bridge(&statement.h)?;
        let y_ng = compress_via_bridge(&statement.y)?;
        let cp_ng = compress_via_bridge(&statement.c_prime)?;
        let dp_ng = compress_via_bridge(&statement.d_prime)?;
        let ep_ng = compress_via_bridge(&statement.e_prime)?;

        let mut zt = rekey_zkp_transcript(transcript);
        let mut verifier = Verifier::new(ZKP_PROOF_LABEL, &mut zt);

        let var_s = verifier.allocate_scalar(b"s");
        let var_rp = verifier.allocate_scalar(b"r_prime");
        let var_rpp = verifier.allocate_scalar(b"r_double_prime");

        let var_f = verifier
            .allocate_point(b"F", f_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "serial_validity" })?;
        let var_g = verifier
            .allocate_point(b"G", g_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "serial_validity" })?;
        let var_h = verifier
            .allocate_point(b"H", h_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "serial_validity" })?;
        let var_y = verifier
            .allocate_point(b"Y", y_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "serial_validity" })?;
        let var_cp = verifier
            .allocate_point(b"C_prime", cp_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "serial_validity" })?;
        let var_dp = verifier
            .allocate_point(b"D_prime", dp_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "serial_validity" })?;
        let var_ep = verifier
            .allocate_point(b"E_prime", ep_ng)
            .map_err(|_| AuraError::VerificationFailed { proof_type: "serial_validity" })?;

        verifier.constrain(var_cp, vec![(var_s, var_g), (var_rp, var_h)]);
        verifier.constrain(var_dp, vec![(var_rpp, var_g)]);
        verifier.constrain(var_ep, vec![(var_s, var_f), (var_rpp, var_y)]);

        verifier
            .verify_compact(&self.inner)
            .map_err(|_| AuraError::VerificationFailed {
                proof_type: "serial_validity",
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;
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
            SerValStatement { f, g, h, y, c_prime, d_prime, e_prime },
            SerValWitness { s, r_prime, r_double_prime },
        )
    }

    #[test]
    fn prove_and_verify() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(&mut rng);

        let mut pt = Transcript::new(b"test-serval-lib");
        let proof = SerialValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-serval-lib");
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

        let mut pt = Transcript::new(b"test-serval-lib");
        let proof = SerialValidityProof::prove(&statement, &bad, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-serval-lib");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }
}
