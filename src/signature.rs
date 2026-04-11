//! Context-bound Schnorr signatures.
//!
//! Used to authenticate messages on the bulletin board.
//! Signatures are bound to the election ID to prevent replay attacks.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use crate::errors::{AuraError, AuraResult};
use crate::transcript::{TranscriptProtocol, DOMAIN_SIGNATURE};
use crate::types::ElectionId;

/// A context-bound Schnorr signature.
#[derive(Debug, Clone)]
pub struct SchnorrSignature {
    /// Commitment `R = k * generator`.
    pub r: CompressedRistretto,
    /// Response `s = k + H(context || R || message) * secret_key`.
    pub s: Scalar,
}

/// Sign a message using a Schnorr signature.
///
/// - `secret_key`: the signing key scalar
/// - `generator`: the base point (e.g., `F` for ballot signatures, `G` for others)
/// - `message`: the message bytes to sign
/// - `election_id`: election context for binding
pub fn sign(
    secret_key: &Scalar,
    generator: &RistrettoPoint,
    message: &[u8],
    election_id: &ElectionId,
    rng: &mut impl CryptoRngCore,
) -> SchnorrSignature {
    let mut transcript = Transcript::new(DOMAIN_SIGNATURE);
    transcript.append_election_id(election_id);
    transcript.append_point(b"gen", &generator.compress());
    transcript.append_point(b"pk", &(secret_key * generator).compress());
    transcript.append_bytes(b"msg", message);

    let k = Scalar::random(rng);
    let r = k * generator;
    let r_compressed = r.compress();

    transcript.append_point(b"R", &r_compressed);
    let challenge = transcript.challenge_scalar(b"c");

    let s = k + challenge * secret_key;

    SchnorrSignature {
        r: r_compressed,
        s,
    }
}

/// Verify a Schnorr signature.
///
/// - `signature`: the signature to verify
/// - `public_key`: the verification key (`secret_key * generator`)
/// - `generator`: the base point
/// - `message`: the signed message
/// - `election_id`: election context
pub fn verify(
    signature: &SchnorrSignature,
    public_key: &RistrettoPoint,
    generator: &RistrettoPoint,
    message: &[u8],
    election_id: &ElectionId,
) -> AuraResult<()> {
    let mut transcript = Transcript::new(DOMAIN_SIGNATURE);
    transcript.append_election_id(election_id);
    transcript.append_point(b"gen", &generator.compress());
    transcript.append_point(b"pk", &public_key.compress());
    transcript.append_bytes(b"msg", message);

    let r_point = signature
        .r
        .decompress()
        .ok_or(AuraError::InvalidSignature)?;

    transcript.append_point(b"R", &signature.r);
    let challenge = transcript.challenge_scalar(b"c");

    // Check: s * G == R + c * PK
    let lhs = signature.s * generator;
    let rhs = r_point + challenge * public_key;

    if lhs == rhs {
        Ok(())
    } else {
        Err(AuraError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let pk = sk * g;
        let eid = ElectionId(b"test-election".to_vec());

        let sig = sign(&sk, &g, b"hello world", &eid, &mut rng);
        verify(&sig, &pk, &g, b"hello world", &eid).unwrap();
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let pk = sk * g;
        let eid = ElectionId(b"test".to_vec());

        let sig = sign(&sk, &g, b"message a", &eid, &mut rng);
        assert!(verify(&sig, &pk, &g, b"message b", &eid).is_err());
    }

    #[test]
    fn wrong_election_id_fails() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let pk = sk * g;

        let eid1 = ElectionId(b"election-1".to_vec());
        let eid2 = ElectionId(b"election-2".to_vec());

        let sig = sign(&sk, &g, b"msg", &eid1, &mut rng);
        assert!(verify(&sig, &pk, &g, b"msg", &eid2).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let wrong_pk = Scalar::random(&mut rng) * g;
        let eid = ElectionId(b"test".to_vec());

        let sig = sign(&sk, &g, b"msg", &eid, &mut rng);
        assert!(verify(&sig, &wrong_pk, &g, b"msg", &eid).is_err());
    }
}
