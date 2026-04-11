use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

/// A point in the Ristretto group.
pub type Point = RistrettoPoint;

/// A compressed point for serialization and storage.
pub type CompressedPoint = CompressedRistretto;

/// Index of a voter in the voter list, in `[0, N_voters)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VoterIndex(pub u32);

/// Index of a tallier in the tallier list, in `[1, N_tally]`.
/// 1-indexed per paper convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TallierIndex(pub u32);

impl TallierIndex {
    /// Convert to a scalar for polynomial evaluation.
    pub fn to_scalar(self) -> Scalar {
        Scalar::from(self.0)
    }
}

/// Index of a candidate/choice, in `[0, k)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChoiceIndex(pub u32);

/// Election identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ElectionId(pub Vec<u8>);

/// A Pedersen commitment `C = sG + rH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PedersenCommitment(pub Point);

impl PedersenCommitment {
    /// Create a Pedersen commitment: `value * G + blinding * H`.
    pub fn commit(value: &Scalar, blinding: &Scalar, g: &Point, h: &Point) -> Self {
        Self(value * g + blinding * h)
    }

    /// Get the underlying point.
    pub fn point(&self) -> &Point {
        &self.0
    }

    /// Compress for storage.
    pub fn compress(&self) -> CompressedPoint {
        self.0.compress()
    }
}

/// ElGamal ciphertext `(D, E)` where `D = rG`, `E = rY + mH_i`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ciphertext {
    pub d: Point,
    pub e: Point,
}

impl Ciphertext {
    /// Add two ciphertexts component-wise (homomorphic addition).
    pub fn add(&self, other: &Ciphertext) -> Ciphertext {
        Ciphertext {
            d: self.d + other.d,
            e: self.e + other.e,
        }
    }
}

impl core::ops::Add for Ciphertext {
    type Output = Ciphertext;

    fn add(self, rhs: Ciphertext) -> Ciphertext {
        Ciphertext {
            d: self.d + rhs.d,
            e: self.e + rhs.e,
        }
    }
}

impl core::iter::Sum for Ciphertext {
    fn sum<I: Iterator<Item = Ciphertext>>(iter: I) -> Self {
        use curve25519_dalek::traits::Identity;
        iter.fold(
            Ciphertext {
                d: Point::identity(),
                e: Point::identity(),
            },
            |acc, ct| acc + ct,
        )
    }
}
