//! Library-backed DLEQ proof via [`sigma_protocols`].
//!
//! Stack: `sigma-protocols` 0.5 + `curve25519-dalek` 4.1 — same major as Aura's
//! home stack, so no byte bridge is needed for points/scalars. The library
//! does its own Fiat-Shamir via `FiatShamirTransform`, but to bind the proof
//! to Aura's protocol-level merlin context (election ID, partial decryption
//! context, etc.) we derive the challenge from the caller-supplied `merlin`
//! transcript and use the library's lower-level prover/verifier API.
//!
//! RNG note: `sigma_protocols::utils::random_scalar` is hard-coded to `OsRng`
//! (no RNG injection point in the public API), so the `rng` argument here is
//! only used for the rare statement-level operations that need it.
//! Deterministic benchmark RNGs (e.g. `ChaCha20`) won't drive the prover's
//! nonce sampling; this is a known limitation of `sigma-protocols 0.5`.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::CryptoRngCore;
use sigma_protocols::protocols::dleq::{DLEQProof, DLEQStatement, DLEQWitness};
use sigma_protocols::sigma::{
    MultiPointCommitment, ScalarChallenge, ScalarResponse, SigmaProtocol,
};

use crate::errors::{AuraError, AuraResult};
use crate::transcript::TranscriptProtocol;

// Re-export the hand-rolled statement/witness so call sites stay identical.
pub use crate::proofs::dleq::{DleqStatement, DleqWitness};

const DOMAIN: &[u8] = b"aura/lib-dleq/sigma-protocols/v1";

/// Library-backed DLEQ proof. Wire layout: 2 commitment points + 1 response scalar.
#[derive(Debug, Clone)]
pub struct DleqProof {
    pub commitment_g: CompressedRistretto,
    pub commitment_h: CompressedRistretto,
    pub response: Scalar,
}

impl DleqProof {
    pub fn prove(
        statement: &DleqStatement,
        witness: &DleqWitness,
        transcript: &mut Transcript,
        _rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let lib_stmt = DLEQStatement {
            g: statement.g,
            h: statement.h,
            x: statement.y,        // sigma-protocols calls the result point `x`
            y: statement.y_prime,  // sigma-protocols calls the second result `y`
        };
        let lib_witness = DLEQWitness {
            alpha: witness.scalar,
        };

        let (commitment, state) = DLEQProof::prover_commit(&lib_stmt, &lib_witness);

        let r_g = commitment.0[0].compress();
        let r_h = commitment.0[1].compress();

        let challenge = derive_challenge(transcript, statement, &r_g, &r_h);

        let response = DLEQProof::prover_response(
            &lib_stmt,
            &lib_witness,
            &state,
            &ScalarChallenge(challenge),
        )
        .map_err(|_| AuraError::VerificationFailed { proof_type: "dleq" })?;

        Ok(DleqProof {
            commitment_g: r_g,
            commitment_h: r_h,
            response: response.0,
        })
    }

    pub fn verify(
        &self,
        statement: &DleqStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let lib_stmt = DLEQStatement {
            g: statement.g,
            h: statement.h,
            x: statement.y,
            y: statement.y_prime,
        };

        let r_g_point = self
            .commitment_g
            .decompress()
            .ok_or(AuraError::VerificationFailed { proof_type: "dleq" })?;
        let r_h_point = self
            .commitment_h
            .decompress()
            .ok_or(AuraError::VerificationFailed { proof_type: "dleq" })?;

        let challenge =
            derive_challenge(transcript, statement, &self.commitment_g, &self.commitment_h);

        let commitment = MultiPointCommitment(vec![r_g_point, r_h_point]);
        DLEQProof::verifier(
            &lib_stmt,
            &commitment,
            &ScalarChallenge(challenge),
            &ScalarResponse(self.response),
        )
        .map_err(|_| AuraError::VerificationFailed { proof_type: "dleq" })
    }
}

/// Bind the statement and the prover's commitments to Aura's merlin transcript,
/// then derive the Fiat-Shamir challenge. Same layout in prove and verify.
fn derive_challenge(
    transcript: &mut Transcript,
    statement: &DleqStatement,
    r_g: &CompressedRistretto,
    r_h: &CompressedRistretto,
) -> Scalar {
    transcript.domain_sep(DOMAIN);
    transcript.append_point(b"G", &statement.g.compress());
    transcript.append_point(b"H", &statement.h.compress());
    transcript.append_point(b"Y", &statement.y.compress());
    transcript.append_point(b"Y'", &statement.y_prime.compress());
    transcript.append_point(b"R_G", r_g);
    transcript.append_point(b"R_H", r_h);
    transcript.challenge_scalar(b"c")
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
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

        let mut pt = Transcript::new(b"test-dleq-lib");
        let proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-dleq-lib");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_witness_fails() {
        let mut rng = OsRng;
        let (statement, _) = random_statement_and_witness(&mut rng);
        let bad_witness = DleqWitness {
            scalar: Scalar::random(&mut rng),
        };

        let mut pt = Transcript::new(b"test-dleq-lib");
        let proof = DleqProof::prove(&statement, &bad_witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-dleq-lib");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (statement, witness) = random_statement_and_witness(&mut rng);

        let mut pt = Transcript::new(b"test-dleq-lib");
        let mut proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        proof.response += Scalar::ONE;

        let mut vt = Transcript::new(b"test-dleq-lib");
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
            y_prime: y2 * h, // different dlog
        };
        let witness = DleqWitness { scalar: y1 };

        let mut pt = Transcript::new(b"test-dleq-lib");
        let proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        let mut vt = Transcript::new(b"test-dleq-lib");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }
}
