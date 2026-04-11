//! ElGamal encryption.
//!
//! Encrypts a scalar message `m` using generator `H_i` and public key `Y`:
//! `D = r*G`, `E = r*Y + m*H_i`.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRngCore;

use crate::types::Ciphertext;

use super::keys::ElectionPublicKey;

/// Encrypt a message scalar under the election public key.
///
/// Returns the ciphertext `(D, E)` and the nonce `r` (needed for proofs).
///
/// - `message`: the scalar to encrypt (typically 0 or 1 for votes)
/// - `message_generator`: `H_i` for choice index `i`
/// - `base_generator`: `G`
/// - `public_key`: the election public key `Y`
pub fn encrypt(
    message: &Scalar,
    message_generator: &RistrettoPoint,
    base_generator: &RistrettoPoint,
    public_key: &ElectionPublicKey,
    rng: &mut impl CryptoRngCore,
) -> (Ciphertext, Scalar) {
    let r = Scalar::random(rng);
    let d = r * base_generator;
    let e = r * public_key.point() + message * message_generator;
    (Ciphertext { d, e }, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn encrypt_produces_valid_ciphertext() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let h_i = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let pk = ElectionPublicKey(sk * g);

        let msg = Scalar::ONE;
        let (ct, r) = encrypt(&msg, &h_i, &g, &pk, &mut rng);

        // Verify: D = r*G, E = r*Y + m*H_i
        assert_eq!(ct.d, r * g);
        assert_eq!(ct.e, r * pk.0 + msg * h_i);
    }

    #[test]
    fn different_nonces_different_ciphertexts() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let h_i = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let pk = ElectionPublicKey(sk * g);

        let msg = Scalar::ZERO;
        let (ct1, _) = encrypt(&msg, &h_i, &g, &pk, &mut rng);
        let (ct2, _) = encrypt(&msg, &h_i, &g, &pk, &mut rng);

        // Same message, different nonces → different ciphertexts
        assert_ne!(ct1.d, ct2.d);
    }
}
