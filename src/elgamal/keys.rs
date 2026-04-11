//! ElGamal key types for the threshold encryption system.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

use crate::proofs::representation::RepresentationProof;
use crate::types::TallierIndex;

/// A tallier's private key share (zeroized on drop).
pub struct KeyShare {
    /// Tallier index (1-indexed).
    pub index: TallierIndex,
    /// Private key share: `y_alpha = sum(y_{beta,alpha})` for all beta.
    pub share: Scalar,
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

impl KeyShare {
    pub fn new(index: TallierIndex, share: Scalar) -> Self {
        Self { index, share }
    }

    /// Compute the corresponding public key share `Y_alpha = y_alpha * G`.
    pub fn public_key_share(&self, g: &RistrettoPoint) -> RistrettoPoint {
        self.share * g
    }
}

/// A tallier's public key share with proof of knowledge.
#[derive(Debug, Clone)]
pub struct PublicKeyShare {
    /// Tallier index (1-indexed).
    pub index: TallierIndex,
    /// Public key share point `Y_alpha = y_alpha * G`.
    pub point: RistrettoPoint,
    /// Proof of knowledge of the discrete log `y_alpha`.
    pub proof: RepresentationProof,
}

/// The aggregated election public key `Y = sum(Y_alpha)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionPublicKey(pub RistrettoPoint);

impl ElectionPublicKey {
    /// Aggregate public key shares into the election public key.
    pub fn from_shares(shares: &[PublicKeyShare]) -> Self {
        let sum: RistrettoPoint = shares.iter().map(|s| s.point).sum();
        Self(sum)
    }

    /// Get the underlying point.
    pub fn point(&self) -> &RistrettoPoint {
        &self.0
    }
}
