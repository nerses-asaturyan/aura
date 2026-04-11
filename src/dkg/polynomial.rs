//! Secret polynomial and Feldman commitments for Pedersen DKG.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

/// A secret polynomial `f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}`.
///
/// Used in the Pedersen DKG protocol for threshold key generation.
pub struct SecretPolynomial {
    /// Coefficients `a_0, a_1, ..., a_{t-1}`.
    coefficients: Vec<Scalar>,
}

impl Drop for SecretPolynomial {
    fn drop(&mut self) {
        for c in &mut self.coefficients {
            c.zeroize();
        }
    }
}

impl SecretPolynomial {
    /// Generate a random polynomial of degree `threshold - 1`.
    pub fn random(threshold: u32, rng: &mut impl CryptoRngCore) -> Self {
        let coefficients: Vec<Scalar> = (0..threshold).map(|_| Scalar::random(rng)).collect();
        Self { coefficients }
    }

    /// Evaluate the polynomial at a given point: `f(x) = sum(a_j * x^j)`.
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        // Horner's method
        let mut result = Scalar::ZERO;
        for coeff in self.coefficients.iter().rev() {
            result = result * x + coeff;
        }
        result
    }

    /// Compute the Feldman commitment: `C_j = a_j * G` for each coefficient.
    pub fn feldman_commitment(&self, g: &RistrettoPoint) -> FeldmanCommitment {
        let commitments = self
            .coefficients
            .iter()
            .map(|a| a * g)
            .collect();
        FeldmanCommitment { commitments }
    }

    /// Get the constant term `a_0` (the secret).
    pub fn secret(&self) -> &Scalar {
        &self.coefficients[0]
    }

    /// Get the threshold (degree + 1).
    pub fn threshold(&self) -> u32 {
        self.coefficients.len() as u32
    }
}

/// Feldman commitment: `{C_j = a_j * G}` for each polynomial coefficient.
///
/// Allows verification of secret shares without revealing the polynomial.
#[derive(Debug, Clone)]
pub struct FeldmanCommitment {
    /// Commitment points `C_0, C_1, ..., C_{t-1}`.
    pub commitments: Vec<RistrettoPoint>,
}

impl FeldmanCommitment {
    /// Verify that a received share is consistent with the Feldman commitment.
    ///
    /// Checks: `sum(alpha^j * C_j) == share * G`
    /// where `alpha` is the recipient's index (as a scalar).
    pub fn verify_share(
        &self,
        recipient_index: &Scalar,
        share: &Scalar,
        g: &RistrettoPoint,
    ) -> bool {
        // Compute sum(alpha^j * C_j) using Horner's method on points
        let mut result = RistrettoPoint::default();
        for c in self.commitments.iter().rev() {
            result = recipient_index * result + c;
        }

        // Check: result == share * G
        result == share * g
    }

    /// Get the public key commitment `C_0 = a_0 * G`.
    pub fn public_key_commitment(&self) -> &RistrettoPoint {
        &self.commitments[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn polynomial_evaluation() {
        let mut rng = OsRng;
        // f(x) = a0 + a1*x (threshold 2)
        let poly = SecretPolynomial::random(2, &mut rng);
        let x = Scalar::from(5u64);
        let y = poly.evaluate(&x);

        // Manually compute
        let expected = poly.coefficients[0] + poly.coefficients[1] * x;
        assert_eq!(y, expected);
    }

    #[test]
    fn feldman_commitment_verify_share() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);

        let poly = SecretPolynomial::random(3, &mut rng); // threshold 3
        let commitment = poly.feldman_commitment(&g);

        // Share for index 1
        let idx = Scalar::from(1u64);
        let share = poly.evaluate(&idx);
        assert!(commitment.verify_share(&idx, &share, &g));

        // Share for index 7
        let idx7 = Scalar::from(7u64);
        let share7 = poly.evaluate(&idx7);
        assert!(commitment.verify_share(&idx7, &share7, &g));

        // Wrong share should fail
        let bad_share = share + Scalar::ONE;
        assert!(!commitment.verify_share(&idx, &bad_share, &g));
    }

    #[test]
    fn feldman_public_key_commitment() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);

        let poly = SecretPolynomial::random(2, &mut rng);
        let commitment = poly.feldman_commitment(&g);

        assert_eq!(*commitment.public_key_commitment(), poly.secret() * g);
    }
}
