//! Tally and result verification.
//!
//! Implements the `Tally` and `VerifyTally` algorithms from the paper.

use curve25519_dalek::ristretto::RistrettoPoint;
use merlin::Transcript;
use rand_core::CryptoRngCore;

use crate::elgamal::decrypt::{self, PartialDecryption};
use crate::elgamal::keys::{KeyShare, PublicKeyShare};
use crate::errors::{AuraError, AuraResult};
use crate::signature;
use crate::types::{Ciphertext, ChoiceIndex};

use super::ballot::Ballot;
use super::params::ElectionParams;

/// A tallier's partial decryption of ballot serial numbers.
#[derive(Debug, Clone)]
pub struct SerialPartialDecryption {
    pub ballot_index: usize,
    pub partial: PartialDecryption,
}

/// A tallier's partial decryption of aggregated vote ciphertexts.
#[derive(Debug, Clone)]
pub struct VotePartialDecryption {
    pub choice: ChoiceIndex,
    pub partial: PartialDecryption,
}

/// The final election result.
#[derive(Debug, Clone)]
pub struct ElectionResult {
    /// Vote count for each choice.
    pub tally: Vec<(ChoiceIndex, u64)>,
    /// Number of valid ballots included in the tally.
    pub valid_ballot_count: usize,
    /// Number of duplicate ballots removed.
    pub duplicate_count: usize,
}

/// Phase 1: Each tallier partially decrypts all ballot serial numbers.
pub fn tally_serial_decrypt(
    key_share: &KeyShare,
    public_share_point: &RistrettoPoint,
    ballots: &[Ballot],
    params: &ElectionParams,
    rng: &mut impl CryptoRngCore,
) -> AuraResult<Vec<SerialPartialDecryption>> {
    let g = params.generators.g;
    let mut results = Vec::with_capacity(ballots.len());

    for (i, ballot) in ballots.iter().enumerate() {
        let mut transcript = Transcript::new(b"aura-serial-dec");
        let pd = PartialDecryption::create(
            key_share,
            &ballot.encrypted_serial,
            &g,
            public_share_point,
            &mut transcript,
            rng,
        )?;
        results.push(SerialPartialDecryption {
            ballot_index: i,
            partial: pd,
        });
    }

    Ok(results)
}

/// Phase 2: Deduplicate ballots by decrypted serial number, then decrypt vote sums.
///
/// Returns the election result with vote counts per choice.
pub fn tally_and_verify(
    ballots: &[Ballot],
    serial_partials: &[Vec<SerialPartialDecryption>], // one vec per tallier
    _public_shares: &[PublicKeyShare],
    params: &ElectionParams,
    _rng: &mut impl CryptoRngCore,
) -> AuraResult<(Vec<usize>, Vec<Ciphertext>)> {
    let _g = params.generators.g;
    let f = params.generators.f;
    let k = params.num_choices as usize;

    // Phase 2a: Decrypt serial numbers to deduplicate.
    let mut serial_public_keys: Vec<Option<RistrettoPoint>> = vec![None; ballots.len()];

    for i in 0..ballots.len() {
        // Collect partial decryptions for ballot i from all talliers.
        let partials: Vec<PartialDecryption> = serial_partials
            .iter()
            .filter_map(|tallier_partials| {
                tallier_partials
                    .iter()
                    .find(|p| p.ballot_index == i)
                    .map(|p| p.partial.clone())
            })
            .collect();

        if partials.len() < params.threshold as usize {
            continue; // Skip ballots without enough partial decryptions
        }

        // Combine partial decryptions to get S_i = s_i * F (without brute-forcing dlog)
        let s_i = decrypt::combine_partial_decryptions(&ballots[i].encrypted_serial, &partials);
        serial_public_keys[i] = Some(s_i);
    }

    // Verify signatures using recovered serial public keys.
    let ballot_message = b"aura-ballot-binding";
    for (i, ballot) in ballots.iter().enumerate() {
        if let Some(ref s_i) = serial_public_keys[i] {
            // Verify signature using S_i as public key against generator F
            if signature::verify(
                &ballot.signature,
                s_i,
                &f,
                ballot_message,
                &params.election_id,
            )
            .is_err()
            {
                serial_public_keys[i] = None; // Invalid signature, exclude
            }
        }
    }

    // Deduplicate: if multiple ballots share the same serial public key,
    // keep only the last one (by index, simulating bulletin board ordering).
    let mut valid_indices: Vec<usize> = Vec::new();
    let mut seen_keys: Vec<(RistrettoPoint, usize)> = Vec::new();

    for (i, key_opt) in serial_public_keys.iter().enumerate() {
        if let Some(key) = key_opt {
            if let Some(pos) = seen_keys.iter().position(|(k, _)| k == key) {
                // Duplicate: replace with later ballot
                seen_keys[pos].1 = i;
            } else {
                seen_keys.push((*key, i));
            }
        }
    }

    let _duplicate_count = ballots.len() - seen_keys.len();
    valid_indices.extend(seen_keys.iter().map(|(_, idx)| *idx));
    valid_indices.sort();

    // Phase 2b: Sum ciphertexts for each choice across valid ballots.
    let mut vote_sums: Vec<Ciphertext> = Vec::with_capacity(k);
    for l in 0..k {
        let sum: Ciphertext = valid_indices
            .iter()
            .map(|&i| ballots[i].encrypted_choices[l].0)
            .sum();
        vote_sums.push(sum);
    }

    Ok((valid_indices, vote_sums))
}

/// Phase 3: Each tallier partially decrypts the vote sums.
pub fn tally_vote_decrypt(
    key_share: &KeyShare,
    public_share_point: &RistrettoPoint,
    vote_sums: &[Ciphertext],
    params: &ElectionParams,
    rng: &mut impl CryptoRngCore,
) -> AuraResult<Vec<VotePartialDecryption>> {
    let g = params.generators.g;
    let mut results = Vec::with_capacity(vote_sums.len());

    for (l, sum_ct) in vote_sums.iter().enumerate() {
        let mut transcript = Transcript::new(b"aura-vote-dec");
        let pd = PartialDecryption::create(
            key_share,
            sum_ct,
            &g,
            public_share_point,
            &mut transcript,
            rng,
        )?;
        results.push(VotePartialDecryption {
            choice: ChoiceIndex(l as u32),
            partial: pd,
        });
    }

    Ok(results)
}

/// Final result computation: combine vote partial decryptions to get tallies.
pub fn compute_result(
    vote_sums: &[Ciphertext],
    vote_partials: &[Vec<VotePartialDecryption>], // one vec per tallier
    _public_shares: &[PublicKeyShare],
    params: &ElectionParams,
    valid_ballot_count: usize,
    duplicate_count: usize,
) -> AuraResult<ElectionResult> {
    let k = params.num_choices as usize;
    let mut tally = Vec::with_capacity(k);

    for l in 0..k {
        // Collect partials for choice l from all talliers
        let partials: Vec<PartialDecryption> = vote_partials
            .iter()
            .filter_map(|tallier_partials| {
                tallier_partials
                    .iter()
                    .find(|p| p.choice == ChoiceIndex(l as u32))
                    .map(|p| p.partial.clone())
            })
            .collect();

        if partials.len() < params.threshold as usize {
            return Err(AuraError::ThresholdNotMet {
                required: params.threshold,
                available: partials.len() as u32,
            });
        }

        // Combine partial decryptions
        let message_point =
            decrypt::combine_partial_decryptions(&vote_sums[l], &partials);

        // Solve discrete log to get vote count
        let count = decrypt::solve_dlog(
            &message_point,
            &params.generators.h_msg[l],
            valid_ballot_count as u64,
        )
        .ok_or(AuraError::DecryptionFailed)?;

        tally.push((ChoiceIndex(l as u32), count));
    }

    Ok(ElectionResult {
        tally,
        valid_ballot_count,
        duplicate_count,
    })
}
