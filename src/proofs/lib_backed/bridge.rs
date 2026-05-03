//! Byte-level conversions between the curve / merlin / rand stacks of the
//! various library backends and Aura's primary `curve25519-dalek 4.1` stack.
//!
//! All conversions go through the canonical 32-byte Ristretto255 encoding for
//! points and the canonical 32-byte little-endian encoding for scalars. Both
//! encodings are standardized and bit-identical across all dalek versions, so
//! roundtripping is faithful.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

use crate::errors::{AuraError, AuraResult};

// -- dalek 4.1 (Aura's home stack) ↔ raw bytes ---------------------------------

#[inline]
pub fn point_to_bytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

#[inline]
pub fn point_from_bytes(bytes: &[u8; 32], proof_type: &'static str) -> AuraResult<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes)
        .map_err(|_| AuraError::VerificationFailed { proof_type })?
        .decompress()
        .ok_or(AuraError::VerificationFailed { proof_type })
}

#[inline]
pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_bytes()
}

#[inline]
pub fn scalar_from_bytes(bytes: &[u8; 32], proof_type: &'static str) -> AuraResult<Scalar> {
    Option::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or(AuraError::VerificationFailed { proof_type })
}

// -- dalek-ng 3 (zkp) ↔ raw bytes ----------------------------------------------

pub mod dalek_ng {
    use super::{AuraError, AuraResult};
    use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek_ng::scalar::Scalar;

    #[inline]
    pub fn point_from_bytes(
        bytes: &[u8; 32],
        proof_type: &'static str,
    ) -> AuraResult<RistrettoPoint> {
        CompressedRistretto::from_slice(bytes)
            .decompress()
            .ok_or(AuraError::VerificationFailed { proof_type })
    }

    #[inline]
    pub fn point_to_bytes(p: &RistrettoPoint) -> [u8; 32] {
        p.compress().to_bytes()
    }

    #[inline]
    pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
        s.to_bytes()
    }

    #[inline]
    pub fn scalar_from_bytes(
        bytes: &[u8; 32],
        proof_type: &'static str,
    ) -> AuraResult<Scalar> {
        Option::from(Scalar::from_canonical_bytes(*bytes))
            .ok_or(AuraError::VerificationFailed { proof_type })
    }
}

// -- dalek 2 (one-of-many-proofs) ↔ raw bytes ----------------------------------

pub mod dalek_v2 {
    use super::{AuraError, AuraResult};
    use curve25519_dalek_v2::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek_v2::scalar::Scalar;

    #[inline]
    pub fn point_from_bytes(
        bytes: &[u8; 32],
        proof_type: &'static str,
    ) -> AuraResult<RistrettoPoint> {
        CompressedRistretto::from_slice(bytes)
            .decompress()
            .ok_or(AuraError::VerificationFailed { proof_type })
    }

    #[inline]
    pub fn point_to_bytes(p: &RistrettoPoint) -> [u8; 32] {
        p.compress().to_bytes()
    }

    #[inline]
    pub fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
        s.to_bytes()
    }

    #[inline]
    pub fn scalar_from_bytes(
        bytes: &[u8; 32],
        proof_type: &'static str,
    ) -> AuraResult<Scalar> {
        Scalar::from_canonical_bytes(*bytes)
            .ok_or(AuraError::VerificationFailed { proof_type })
    }
}

// -- rand 0.8 (Aura) ↔ rand 0.7 (zkp / one-of-many-proofs) ---------------------

/// Adapter that lets a modern `rand_core::CryptoRngCore` (rand 0.8) drive the
/// `rand_core 0.5` `RngCore + CryptoRng` traits expected by `zkp` 0.8 and
/// `one-of-many-proofs` 0.1.
pub struct Rng07Adapter<'a, R: rand_core::CryptoRngCore + ?Sized>(pub &'a mut R);

impl<R: rand_core::CryptoRngCore + ?Sized> rand07::RngCore for Rng07Adapter<'_, R> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.0.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.0.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand07::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: rand_core::CryptoRngCore + ?Sized> rand07::CryptoRng for Rng07Adapter<'_, R> {}
