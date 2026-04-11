//! Pedersen DKG protocol for distributed threshold key generation.
//!
//! Implements the KeyGen algorithm from the paper (Section 2.1):
//! 1. Each tallier generates a random polynomial and broadcasts Feldman commitments
//! 2. Each tallier sends secret shares to all others via private channels
//! 3. Each tallier verifies received shares and computes their aggregate key share

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use crate::elgamal::keys::{ElectionPublicKey, KeyShare, PublicKeyShare};
use crate::errors::{AuraError, AuraResult};
use crate::proofs::representation::{
    RepresentationProof, RepresentationStatement, RepresentationWitness,
};
use crate::types::TallierIndex;

use super::polynomial::{FeldmanCommitment, SecretPolynomial};

/// Output of DKG round 1: Feldman commitment and proof of knowledge of `a_0`.
#[derive(Debug, Clone)]
pub struct DkgRound1Output {
    /// Tallier index.
    pub index: TallierIndex,
    /// Feldman commitment to the polynomial coefficients.
    pub commitment: FeldmanCommitment,
    /// Proof of knowledge of `a_0` (the secret contribution).
    pub rep_proof: RepresentationProof,
}

/// Output of DKG round 2: shares to send privately to each other tallier.
pub struct DkgRound2Output {
    /// `shares[i] = (TallierIndex(i+1), f_alpha(i+1))` for each tallier.
    pub shares: Vec<(TallierIndex, Scalar)>,
}

/// Final result of the DKG protocol for a single tallier.
pub struct DkgResult {
    /// This tallier's private key share.
    pub key_share: KeyShare,
    /// This tallier's public key share with proof.
    pub public_share: PublicKeyShare,
    /// The election public key.
    pub election_public_key: ElectionPublicKey,
}

/// DKG Round 1: Generate polynomial, produce Feldman commitment and proof.
pub fn dkg_round1(
    index: TallierIndex,
    threshold: u32,
    g: &RistrettoPoint,
    rng: &mut impl CryptoRngCore,
) -> (SecretPolynomial, DkgRound1Output) {
    let poly = SecretPolynomial::random(threshold, rng);
    let commitment = poly.feldman_commitment(g);

    // Proof of knowledge of a_0
    let statement = RepresentationStatement {
        generators: vec![*g],
        target: *commitment.public_key_commitment(),
    };
    let witness = RepresentationWitness {
        scalars: vec![*poly.secret()],
    };

    let mut transcript = Transcript::new(b"aura-dkg-round1");
    let rep_proof =
        RepresentationProof::prove(&statement, &witness, &mut transcript, rng).unwrap();

    let output = DkgRound1Output {
        index,
        commitment,
        rep_proof,
    };

    (poly, output)
}

/// Verify a round 1 output from another tallier.
pub fn verify_round1(output: &DkgRound1Output, g: &RistrettoPoint) -> AuraResult<()> {
    let statement = RepresentationStatement {
        generators: vec![*g],
        target: *output.commitment.public_key_commitment(),
    };

    let mut transcript = Transcript::new(b"aura-dkg-round1");
    output.rep_proof.verify(&statement, &mut transcript)
}

/// DKG Round 2: Compute shares to send to each other tallier.
pub fn dkg_round2(
    polynomial: &SecretPolynomial,
    num_talliers: u32,
) -> DkgRound2Output {
    let shares = (1..=num_talliers)
        .map(|beta| {
            let idx = TallierIndex(beta);
            let share = polynomial.evaluate(&idx.to_scalar());
            (idx, share)
        })
        .collect();

    DkgRound2Output { shares }
}

/// DKG Finalize: Verify received shares and compute the aggregate key share.
///
/// - `index`: this tallier's index
/// - `own_polynomial`: this tallier's secret polynomial
/// - `received_shares`: shares received from other talliers `(sender_index, share_value)`
/// - `all_round1`: all round 1 outputs (including own)
/// - `g`: base generator
pub fn dkg_finalize(
    index: TallierIndex,
    own_polynomial: &SecretPolynomial,
    received_shares: &[(TallierIndex, Scalar)],
    all_round1: &[DkgRound1Output],
    g: &RistrettoPoint,
    rng: &mut impl CryptoRngCore,
) -> AuraResult<DkgResult> {
    let my_index_scalar = index.to_scalar();

    // Verify each received share against the sender's Feldman commitment
    for (sender_idx, share_val) in received_shares {
        let round1 = all_round1
            .iter()
            .find(|r| r.index == *sender_idx)
            .ok_or(AuraError::DkgError {
                reason: format!("missing round1 output for tallier {:?}", sender_idx),
            })?;

        if !round1
            .commitment
            .verify_share(&my_index_scalar, share_val, g)
        {
            return Err(AuraError::DkgError {
                reason: format!(
                    "invalid share from tallier {:?} to tallier {:?}",
                    sender_idx, index
                ),
            });
        }
    }

    // Compute aggregate private key share: y_alpha = sum of all shares for this index
    // This includes our own share f_alpha(alpha)
    let own_share = own_polynomial.evaluate(&my_index_scalar);
    let mut y_alpha = own_share;
    for (_, share_val) in received_shares {
        y_alpha += share_val;
    }

    // Compute public key share
    let y_alpha_point = y_alpha * g;

    // Compute election public key: Y = sum(C_{beta,0}) for all talliers
    let election_pk_point: RistrettoPoint = all_round1
        .iter()
        .map(|r| *r.commitment.public_key_commitment())
        .sum();

    // Produce proof of knowledge of key share
    let statement = RepresentationStatement {
        generators: vec![*g],
        target: y_alpha_point,
    };
    let witness = RepresentationWitness {
        scalars: vec![y_alpha],
    };
    let mut transcript = Transcript::new(b"aura-dkg-keyproof");
    let key_proof = RepresentationProof::prove(&statement, &witness, &mut transcript, rng)?;

    Ok(DkgResult {
        key_share: KeyShare::new(index, y_alpha),
        public_share: PublicKeyShare {
            index,
            point: y_alpha_point,
            proof: key_proof,
        },
        election_public_key: ElectionPublicKey(election_pk_point),
    })
}

/// Verify all key shares and compute the election public key.
///
/// This is `VerifyKeyGen` from the paper. The election public key
/// is computed from the Feldman commitments (`Y = sum(C_{beta,0})`),
/// not from summing Y_alpha directly (which would be incorrect since
/// Y_alpha are polynomial evaluations at non-zero indices).
pub fn verify_key_gen(
    public_shares: &[PublicKeyShare],
    round1_outputs: &[DkgRound1Output],
    g: &RistrettoPoint,
) -> AuraResult<ElectionPublicKey> {
    // Verify each key share proof
    for share in public_shares {
        let statement = RepresentationStatement {
            generators: vec![*g],
            target: share.point,
        };
        let mut transcript = Transcript::new(b"aura-dkg-keyproof");
        share.proof.verify(&statement, &mut transcript)?;
    }

    // Compute election public key from Feldman commitments
    let election_pk_point: RistrettoPoint = round1_outputs
        .iter()
        .map(|r| *r.commitment.public_key_commitment())
        .sum();

    Ok(ElectionPublicKey(election_pk_point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Run a complete DKG protocol with the given parameters.
    fn run_dkg(
        num_talliers: u32,
        threshold: u32,
    ) -> (Vec<DkgResult>, ElectionPublicKey) {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);

        // Round 1: each tallier generates polynomial and commitment
        let mut polynomials = Vec::new();
        let mut round1_outputs = Vec::new();
        for alpha in 1..=num_talliers {
            let (poly, output) = dkg_round1(TallierIndex(alpha), threshold, &g, &mut rng);
            polynomials.push(poly);
            round1_outputs.push(output);
        }

        // Verify all round 1 outputs
        for output in &round1_outputs {
            verify_round1(output, &g).unwrap();
        }

        // Round 2: compute shares
        let mut all_round2: Vec<DkgRound2Output> = Vec::new();
        for poly in &polynomials {
            all_round2.push(dkg_round2(poly, num_talliers));
        }

        // Finalize: each tallier collects shares from others and computes key share
        let mut results = Vec::new();
        for alpha in 1..=num_talliers {
            let alpha_idx = (alpha - 1) as usize;

            // Collect shares sent to this tallier from all OTHER talliers
            let received_shares: Vec<(TallierIndex, Scalar)> = (0..num_talliers as usize)
                .filter(|&beta_idx| beta_idx != alpha_idx)
                .map(|beta_idx| {
                    let share = all_round2[beta_idx]
                        .shares
                        .iter()
                        .find(|(idx, _)| *idx == TallierIndex(alpha))
                        .unwrap()
                        .1;
                    (TallierIndex((beta_idx + 1) as u32), share)
                })
                .collect();

            let result = dkg_finalize(
                TallierIndex(alpha),
                &polynomials[alpha_idx],
                &received_shares,
                &round1_outputs,
                &g,
                &mut rng,
            )
            .unwrap();

            results.push(result);
        }

        // All talliers should agree on the election public key
        let epk = results[0].election_public_key;
        for r in &results[1..] {
            assert_eq!(r.election_public_key, epk);
        }

        // Verify key generation
        let public_shares: Vec<PublicKeyShare> =
            results.iter().map(|r| r.public_share.clone()).collect();
        let verified_epk = verify_key_gen(&public_shares, &round1_outputs, &g).unwrap();
        assert_eq!(verified_epk, epk);

        (results, epk)
    }

    #[test]
    fn dkg_2_of_3() {
        let (results, _epk) = run_dkg(3, 2);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn dkg_3_of_5() {
        let (results, _epk) = run_dkg(5, 3);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn dkg_1_of_1() {
        let (results, _epk) = run_dkg(1, 1);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn dkg_threshold_decryption() {
        // Full end-to-end: DKG → encrypt → threshold decrypt
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);
        let h_i = RistrettoPoint::random(&mut rng);

        // Run 2-of-3 DKG
        let num_talliers = 3u32;
        let threshold = 2u32;

        let mut polynomials = Vec::new();
        let mut round1_outputs = Vec::new();
        for alpha in 1..=num_talliers {
            let (poly, output) = dkg_round1(TallierIndex(alpha), threshold, &g, &mut rng);
            polynomials.push(poly);
            round1_outputs.push(output);
        }

        let mut all_round2: Vec<DkgRound2Output> = Vec::new();
        for poly in &polynomials {
            all_round2.push(dkg_round2(poly, num_talliers));
        }

        let mut results = Vec::new();
        for alpha in 1..=num_talliers {
            let alpha_idx = (alpha - 1) as usize;
            let received_shares: Vec<(TallierIndex, Scalar)> = (0..num_talliers as usize)
                .filter(|&beta_idx| beta_idx != alpha_idx)
                .map(|beta_idx| {
                    let share = all_round2[beta_idx]
                        .shares
                        .iter()
                        .find(|(idx, _)| *idx == TallierIndex(alpha))
                        .unwrap()
                        .1;
                    (TallierIndex((beta_idx + 1) as u32), share)
                })
                .collect();

            let result = dkg_finalize(
                TallierIndex(alpha),
                &polynomials[alpha_idx],
                &received_shares,
                &round1_outputs,
                &g,
                &mut rng,
            )
            .unwrap();
            results.push(result);
        }

        let epk = results[0].election_public_key;

        // Encrypt message = 13
        let msg = Scalar::from(13u64);
        let r = Scalar::random(&mut rng);
        let ct = crate::types::Ciphertext {
            d: r * g,
            e: r * epk.0 + msg * h_i,
        };

        // Use talliers 1 and 2 (any 2 of 3)
        let public_shares: Vec<PublicKeyShare> =
            results.iter().map(|r| r.public_share.clone()).collect();

        let mut partials = Vec::new();
        let mut verify_transcripts = Vec::new();
        for i in [0, 1] {
            let ks = &results[i].key_share;
            let mut t = Transcript::new(b"test-dkg-dec");
            let pd = crate::elgamal::decrypt::PartialDecryption::create(
                ks,
                &ct,
                &g,
                &results[i].public_share.point,
                &mut t,
                &mut rng,
            )
            .unwrap();
            partials.push(pd);
            verify_transcripts.push(Transcript::new(b"test-dkg-dec"));
        }

        let result = crate::elgamal::decrypt::verify_and_decrypt(
            &ct,
            &partials,
            &public_shares,
            &g,
            &h_i,
            100,
            &mut verify_transcripts,
        )
        .unwrap();

        assert_eq!(result, 13);
    }

    #[test]
    fn dkg_invalid_share_rejected() {
        let mut rng = OsRng;
        let g = RistrettoPoint::random(&mut rng);

        let (poly1, out1) = dkg_round1(TallierIndex(1), 2, &g, &mut rng);
        let (poly2, out2) = dkg_round1(TallierIndex(2), 2, &g, &mut rng);

        let all_round1 = vec![out1, out2];

        // Compute correct shares from poly2 to tallier 1
        let correct_share = poly2.evaluate(&Scalar::from(1u64));

        // Tamper with the share
        let bad_share = correct_share + Scalar::ONE;
        let received_shares = vec![(TallierIndex(2), bad_share)];

        let result = dkg_finalize(
            TallierIndex(1),
            &poly1,
            &received_shares,
            &all_round1,
            &g,
            &mut rng,
        );

        assert!(result.is_err());
    }
}
