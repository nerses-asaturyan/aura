//! One-out-of-N commitment set membership proof.
//!
//! Proves that for some index `l` in `[0, N)`, the offset `C_l - C' = r*H`
//! (i.e., `C'` is a re-blinding of `C_l`).
//!
//! Based on Bootle et al. (ESORICS 2015) with Spark modifications.
//! Proof size is `O(n * m)` where `N = n^m`, giving logarithmic scaling.
//!
//! The prover uses a recursive layer-by-layer computation of cross-term
//! commitments, achieving O(N) total group operations instead of O(N * m^2).

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use merlin::Transcript;
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use crate::errors::{AuraError, AuraResult};
use crate::transcript::{TranscriptProtocol, DOMAIN_SET_PROOF};

/// Parameters for the commitment set proof.
#[derive(Debug, Clone)]
pub struct CommitmentSetParams {
    pub n: u32,
    pub m: u32,
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

/// Public statement for a commitment set proof.
#[derive(Debug, Clone)]
pub struct CommitmentSetStatement {
    pub params: CommitmentSetParams,
    pub commitments: Vec<RistrettoPoint>,
    pub c_prime: RistrettoPoint,
}

/// Private witness for a commitment set proof.
pub struct CommitmentSetWitness {
    pub index: u32,
    pub blinding: Scalar,
}

impl Drop for CommitmentSetWitness {
    fn drop(&mut self) {
        self.blinding.zeroize();
    }
}

/// One-out-of-N commitment set membership proof.
#[derive(Debug, Clone)]
pub struct CommitmentSetProof {
    /// Digit indicator commitments: `m` vectors of `n` points each.
    pub cl: Vec<Vec<CompressedRistretto>>,
    /// Cross-term commitments: `A_0, ..., A_{m-1}`.
    pub cross_terms: Vec<CompressedRistretto>,
    /// Response scalars: `m` vectors of `n` scalars each.
    pub f_matrix: Vec<Vec<Scalar>>,
    /// Blinding response.
    pub z: Scalar,
}

/// Decompose index `l` in base `n` with `m` digits (least significant first).
fn decompose(l: u32, n: u32, m: u32) -> Vec<u32> {
    let mut digits = Vec::with_capacity(m as usize);
    let mut val = l;
    for _ in 0..m {
        digits.push(val % n);
        val /= n;
    }
    digits
}

/// Multiply two scalar polynomials.
fn poly_mul(a: &[Scalar], b: &[Scalar]) -> Vec<Scalar> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let mut result = vec![Scalar::ZERO; a.len() + b.len() - 1];
    for (i, ai) in a.iter().enumerate() {
        for (j, bj) in b.iter().enumerate() {
            result[i + j] += ai * bj;
        }
    }
    result
}

/// Compute cross-term coefficients P_0, ..., P_{m-1} using MSM.
///
/// For each k, computes `P_k = sum_i p_{i,k} * (C_i - C')` where `p_{i,k}` is
/// the coefficient of `x^k` in `prod_j (delta(l_j, d_j)*x + a_{j,d_j})`.
///
/// Strategy: compute all scalar weights p_{i,k} first (O(N*m^2) scalar ops),
/// then use Pippenger MSM for each k (O(N/log(N)) group ops per k).
/// Total: m MSMs of size N, which is dramatically faster than N individual
/// scalar-point multiplications.
fn compute_cross_terms(
    commitments: &[RistrettoPoint],
    c_prime: &RistrettoPoint,
    n: usize,
    m: usize,
    secret_digits: &[u32],
    a_matrix: &[Vec<Scalar>],
) -> Vec<RistrettoPoint> {
    let big_n = commitments.len();

    // Precompute diffs: C_i - C'
    let diffs: Vec<RistrettoPoint> = commitments.iter().map(|c| c - c_prime).collect();

    // For each index i, compute the polynomial p_i(x) = prod_j factor_j(d_j)
    // and extract coefficient k for each k = 0..m.
    //
    // We store weights[k][i] = p_{i,k} for all i and k.
    // Then P_k = MSM(weights[k], diffs).

    // Compute all weights (scalar-only computation, very fast)
    let mut weights: Vec<Vec<Scalar>> = vec![vec![Scalar::ZERO; big_n]; m + 1];

    for i in 0..big_n {
        let digits_i = decompose(i as u32, n as u32, m as u32);

        // Build polynomial by multiplying factors
        let mut poly = vec![Scalar::ONE]; // start with constant 1
        for j in 0..m {
            let d = digits_i[j] as usize;
            let a_val = a_matrix[j][d];
            let is_match = d == secret_digits[j] as usize;

            if is_match {
                // Factor: x + a_val = [a_val, 1]
                poly = poly_mul(&poly, &[a_val, Scalar::ONE]);
            } else {
                // Factor: a_val = [a_val]
                for coeff in poly.iter_mut() {
                    *coeff *= a_val;
                }
            }
        }

        // Store coefficients
        for (k, coeff) in poly.iter().enumerate() {
            if k <= m {
                weights[k][i] = *coeff;
            }
        }
    }

    // Compute P_k = MSM(weights[k], diffs) for each k
    let mut p_coeffs = Vec::with_capacity(m + 1);
    for k in 0..=m {
        let p_k = RistrettoPoint::vartime_multiscalar_mul(&weights[k], &diffs);
        p_coeffs.push(p_k);
    }

    p_coeffs
}

impl CommitmentSetProof {
    pub fn prove(
        statement: &CommitmentSetStatement,
        witness: &CommitmentSetWitness,
        transcript: &mut Transcript,
        rng: &mut impl CryptoRngCore,
    ) -> AuraResult<Self> {
        let n = statement.params.n as usize;
        let m = statement.params.m as usize;
        let big_n = n.pow(statement.params.m);
        let g = statement.params.g;
        let h = statement.params.h;

        if statement.commitments.len() != big_n {
            return Err(AuraError::InvalidParameter {
                reason: format!(
                    "expected {} commitments, got {}",
                    big_n,
                    statement.commitments.len()
                ),
            });
        }

        let digits = decompose(witness.index, statement.params.n, statement.params.m);

        // Commit statement to transcript
        transcript.domain_sep(DOMAIN_SET_PROOF);
        transcript.append_u64(b"n", n as u64);
        transcript.append_u64(b"m", m as u64);
        transcript.append_point(b"G", &g.compress());
        transcript.append_point(b"H", &h.compress());
        for c in &statement.commitments {
            transcript.append_point(b"C_i", &c.compress());
        }
        transcript.append_point(b"C'", &statement.c_prime.compress());

        // Step 1: Random masks with sum-to-zero constraint per layer.
        let mut a_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(m);
        let mut cl = Vec::with_capacity(m);

        for j in 0..m {
            let mut a_j = Vec::with_capacity(n);
            let mut running_sum = Scalar::ZERO;
            for _sigma in 0..n - 1 {
                let val = Scalar::random(rng);
                running_sum += val;
                a_j.push(val);
            }
            a_j.push(-running_sum);
            a_matrix.push(a_j.clone());

            let mut cl_j = Vec::with_capacity(n);
            for sigma in 0..n {
                let indicator = if sigma == digits[j] as usize {
                    Scalar::ONE
                } else {
                    Scalar::ZERO
                };
                let comm = indicator * g + a_j[sigma] * h;
                cl_j.push(comm.compress());
            }
            cl.push(cl_j);
        }

        // Step 2: Compute cross-term coefficients P_0, ..., P_m via recursive expansion.
        let p_coeffs = compute_cross_terms(
            &statement.commitments,
            &statement.c_prime,
            n,
            m,
            &digits,
            &a_matrix,
        );
        // p_coeffs has m+1 elements; p_coeffs[m] should equal blinding * H

        // Step 3: Cross-term commitments: A_k = P_k + rho_k * H for k = 0..m-1.
        let mut rho: Vec<Scalar> = (0..m).map(|_| Scalar::random(rng)).collect();
        let mut cross_terms = Vec::with_capacity(m);
        for k in 0..m {
            let a_k = p_coeffs[k] + rho[k] * h;
            cross_terms.push(a_k.compress());
        }

        // Commit to transcript
        for j in 0..m {
            for sigma in 0..n {
                transcript.append_point(b"cl", &cl[j][sigma]);
            }
        }
        for k in 0..m {
            transcript.append_point(b"A_k", &cross_terms[k]);
        }

        // Challenge
        let x = transcript.challenge_scalar(b"x");

        // Step 4: Response f_matrix.
        let mut f_matrix = Vec::with_capacity(m);
        for j in 0..m {
            let mut f_j = Vec::with_capacity(n);
            for sigma in 0..n {
                let indicator = if sigma == digits[j] as usize {
                    Scalar::ONE
                } else {
                    Scalar::ZERO
                };
                f_j.push(indicator * x + a_matrix[j][sigma]);
            }
            f_matrix.push(f_j);
        }

        // Step 5: Blinding response: z = blinding * x^m - sum(rho_k * x^k)
        let mut z = Scalar::ZERO;
        let mut x_power = Scalar::ONE;
        for k in 0..m {
            z -= rho[k] * x_power;
            x_power *= x;
        }
        z += witness.blinding * x_power;

        for r in &mut rho {
            r.zeroize();
        }
        for a_j in &mut a_matrix {
            for a in a_j {
                a.zeroize();
            }
        }

        Ok(CommitmentSetProof {
            cl,
            cross_terms,
            f_matrix,
            z,
        })
    }

    pub fn verify(
        &self,
        statement: &CommitmentSetStatement,
        transcript: &mut Transcript,
    ) -> AuraResult<()> {
        let n = statement.params.n as usize;
        let m = statement.params.m as usize;
        let big_n = n.pow(statement.params.m);
        let h = statement.params.h;

        if statement.commitments.len() != big_n
            || self.f_matrix.len() != m
            || self.cl.len() != m
            || self.cross_terms.len() != m
        {
            return Err(AuraError::VerificationFailed {
                proof_type: "commitment_set",
            });
        }

        // Reconstruct transcript
        transcript.domain_sep(DOMAIN_SET_PROOF);
        transcript.append_u64(b"n", n as u64);
        transcript.append_u64(b"m", m as u64);
        transcript.append_point(b"G", &statement.params.g.compress());
        transcript.append_point(b"H", &h.compress());
        for c in &statement.commitments {
            transcript.append_point(b"C_i", &c.compress());
        }
        transcript.append_point(b"C'", &statement.c_prime.compress());
        for j in 0..m {
            for sigma in 0..n {
                transcript.append_point(b"cl", &self.cl[j][sigma]);
            }
        }
        for k in 0..m {
            transcript.append_point(b"A_k", &self.cross_terms[k]);
        }
        let x = transcript.challenge_scalar(b"x");

        // Check 1: Digit consistency — sum_sigma f_{j,sigma} = x
        for j in 0..m {
            if self.f_matrix[j].len() != n {
                return Err(AuraError::VerificationFailed {
                    proof_type: "commitment_set",
                });
            }
            let f_sum: Scalar = self.f_matrix[j].iter().sum();
            if f_sum != x {
                return Err(AuraError::VerificationFailed {
                    proof_type: "commitment_set",
                });
            }
        }

        // Check 2: Main membership equation
        // sum_i p_i(x) * (C_i - C') - sum_k x^k * A_k == z * H
        let mut all_scalars = Vec::with_capacity(big_n + m + 1);
        let mut all_points = Vec::with_capacity(big_n + m + 1);

        for i in 0..big_n {
            let digits_i = decompose(i as u32, statement.params.n, statement.params.m);
            let mut p_i = Scalar::ONE;
            for j in 0..m {
                p_i *= self.f_matrix[j][digits_i[j] as usize];
            }
            all_scalars.push(p_i);
            all_points.push(statement.commitments[i] - statement.c_prime);
        }

        let mut x_power = Scalar::ONE;
        for k in 0..m {
            let a_k =
                self.cross_terms[k]
                    .decompress()
                    .ok_or(AuraError::VerificationFailed {
                        proof_type: "commitment_set",
                    })?;
            all_scalars.push(-x_power);
            all_points.push(a_k);
            x_power *= x;
        }

        all_scalars.push(-self.z);
        all_points.push(h);

        let result = RistrettoPoint::vartime_multiscalar_mul(&all_scalars, &all_points);

        if result != RistrettoPoint::identity() {
            return Err(AuraError::VerificationFailed {
                proof_type: "commitment_set",
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn create_test_set(
        n: u32,
        m: u32,
        secret_index: u32,
        rng: &mut impl CryptoRngCore,
    ) -> (CommitmentSetStatement, CommitmentSetWitness) {
        let big_n = (n as usize).pow(m);
        let g = RistrettoPoint::random(rng);
        let h = RistrettoPoint::random(rng);

        let commitments: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| {
                let s = Scalar::random(rng);
                let r = Scalar::random(rng);
                s * g + r * h
            })
            .collect();

        let blinding = Scalar::random(rng);
        let c_prime = commitments[secret_index as usize] - blinding * h;

        let params = CommitmentSetParams { n, m, g, h };
        (
            CommitmentSetStatement {
                params,
                commitments,
                c_prime,
            },
            CommitmentSetWitness {
                index: secret_index,
                blinding,
            },
        )
    }

    #[test]
    fn prove_and_verify_n2_m3() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 3, 5, &mut rng);
        let mut pt = Transcript::new(b"test-set");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = Transcript::new(b"test-set");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_n4_m2() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(4, 2, 11, &mut rng);
        let mut pt = Transcript::new(b"test-set");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = Transcript::new(b"test-set");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_index_0() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 3, 0, &mut rng);
        let mut pt = Transcript::new(b"test-set");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = Transcript::new(b"test-set");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_last_index() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 3, 7, &mut rng);
        let mut pt = Transcript::new(b"test-set");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = Transcript::new(b"test-set");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn wrong_index_fails() {
        let mut rng = OsRng;
        let (statement, _) = create_test_set(2, 3, 5, &mut rng);
        let bad_witness = CommitmentSetWitness {
            index: 3,
            blinding: Scalar::random(&mut rng),
        };
        let mut pt = Transcript::new(b"test-set");
        let proof =
            CommitmentSetProof::prove(&statement, &bad_witness, &mut pt, &mut rng).unwrap();
        let mut vt = Transcript::new(b"test-set");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 3, 5, &mut rng);
        let mut pt = Transcript::new(b"test-set");
        let mut proof =
            CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        proof.z += Scalar::ONE;
        let mut vt = Transcript::new(b"test-set");
        assert!(proof.verify(&statement, &mut vt).is_err());
    }

    #[test]
    fn prove_and_verify_n2_m4() {
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 4, 10, &mut rng);
        let mut pt = Transcript::new(b"test-set");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = Transcript::new(b"test-set");
        proof.verify(&statement, &mut vt).unwrap();
    }

    #[test]
    fn prove_and_verify_n2_m10() {
        // N = 1024 — moderate scale test
        let mut rng = OsRng;
        let (statement, witness) = create_test_set(2, 10, 500, &mut rng);
        let mut pt = Transcript::new(b"test-set");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        let mut vt = Transcript::new(b"test-set");
        proof.verify(&statement, &mut vt).unwrap();
    }
}
