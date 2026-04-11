//! Full end-to-end election integration test.
//!
//! 8 voters (n=2, m=3), 3 talliers (2-of-3 threshold), 4 candidates, kmin=1, kmax=2.

use aura::dkg::protocol::{self, DkgRound1Output, DkgRound2Output};
use aura::election::ballot::{self, Ballot};
use aura::election::params::{self, ElectionConfig};
use aura::election::setup::{self, VoterRegistration, VoterSecret};
use aura::election::tally;
use aura::elgamal::keys::PublicKeyShare;
use aura::types::{ElectionId, PedersenCommitment, TallierIndex, VoterIndex};
use rand::rngs::OsRng;

/// Run a complete election and verify the result.
#[test]
fn full_election_8_voters_3_talliers_4_candidates() {
    let mut rng = OsRng;

    // === Step 1: Setup Election ===
    let config = ElectionConfig {
        election_id: ElectionId(b"test-election-2026".to_vec()),
        description: "Board election 2026".into(),
        num_choices: 4,
        choice_descriptions: vec![
            "Alice".into(),
            "Bob".into(),
            "Carol".into(),
            "Dave".into(),
        ],
        min_choices: 1,
        max_choices: 2,
        num_voters: 8,  // 2^3
        set_base: 2,
        set_depth: 3,
        num_talliers: 3,
        threshold: 2,
    };

    let params = params::setup_election(config);
    // k' = 4 + 2 - 1 = 5
    assert_eq!(params.padded_choices, 5);

    // === Step 2: Setup Tally (DKG) ===
    let num_talliers = params.num_talliers;
    let threshold = params.threshold;
    let g = params.generators.g;

    let mut polynomials = Vec::new();
    let mut round1_outputs: Vec<DkgRound1Output> = Vec::new();

    for alpha in 1..=num_talliers {
        let (poly, output) =
            protocol::dkg_round1(TallierIndex(alpha), threshold, &g, &mut rng);
        polynomials.push(poly);
        round1_outputs.push(output);
    }

    // Verify round 1
    for output in &round1_outputs {
        protocol::verify_round1(output, &g).unwrap();
    }

    // Round 2: compute and distribute shares
    let mut all_round2: Vec<DkgRound2Output> = Vec::new();
    for poly in &polynomials {
        all_round2.push(protocol::dkg_round2(poly, num_talliers));
    }

    // Finalize DKG
    let mut dkg_results = Vec::new();
    for alpha in 1..=num_talliers {
        let alpha_idx = (alpha - 1) as usize;
        let received_shares: Vec<(TallierIndex, curve25519_dalek::scalar::Scalar)> =
            (0..num_talliers as usize)
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

        let result = protocol::dkg_finalize(
            TallierIndex(alpha),
            &polynomials[alpha_idx],
            &received_shares,
            &round1_outputs,
            &g,
            &mut rng,
        )
        .unwrap();
        dkg_results.push(result);
    }

    let public_shares: Vec<PublicKeyShare> =
        dkg_results.iter().map(|r| r.public_share.clone()).collect();
    let election_key = dkg_results[0].election_public_key;

    // === Step 3: Setup Voters ===
    let mut voter_secrets: Vec<VoterSecret> = Vec::new();
    let mut voter_registrations: Vec<VoterRegistration> = Vec::new();

    for i in 0..params.num_voters {
        let (secret, reg) = setup::setup_voter(VoterIndex(i), &params, &mut rng).unwrap();
        voter_secrets.push(secret);
        voter_registrations.push(reg);
    }

    // === Step 4: Verify Setup ===
    let verified_key = setup::verify_setup(
        &params,
        &public_shares,
        &round1_outputs,
        &voter_registrations,
    )
    .unwrap();
    assert_eq!(verified_key, election_key);

    // === Step 5: Cast Votes ===
    // Voter choices (each picks 1 or 2 out of 4 candidates):
    let voter_choices: Vec<Vec<bool>> = vec![
        vec![true, false, false, true],   // voter 0: Alice, Dave
        vec![false, true, false, false],  // voter 1: Bob
        vec![true, false, true, false],   // voter 2: Alice, Carol
        vec![false, false, true, false],  // voter 3: Carol
        vec![true, true, false, false],   // voter 4: Alice, Bob
        vec![false, true, false, true],   // voter 5: Bob, Dave
        vec![true, false, false, false],  // voter 6: Alice
        vec![false, false, true, true],   // voter 7: Carol, Dave
    ];

    // Expected: Alice=4, Bob=3, Carol=3, Dave=3
    let expected_tally = [4u64, 3, 3, 3];

    let all_ballot_keys: Vec<PedersenCommitment> =
        voter_registrations.iter().map(|r| r.ballot_key).collect();

    let mut ballots: Vec<Ballot> = Vec::new();
    for (i, choices) in voter_choices.iter().enumerate() {
        let b = ballot::vote(
            &voter_secrets[i],
            i as u32,
            choices,
            &params,
            &election_key,
            &all_ballot_keys,
            &mut rng,
        )
        .unwrap();
        ballots.push(b);
    }

    // === Step 6: Verify Ballots ===
    for b in &ballots {
        ballot::verify_ballot(b, &params, &election_key, &all_ballot_keys).unwrap();
    }

    // === Step 7: Tally ===
    // Phase 1: Serial decryption (use talliers 1 and 2, threshold = 2)
    let active_talliers = [0usize, 1]; // indices into dkg_results

    let mut serial_partials: Vec<Vec<tally::SerialPartialDecryption>> = Vec::new();
    for &t_idx in &active_talliers {
        let sp = tally::tally_serial_decrypt(
            &dkg_results[t_idx].key_share,
            &dkg_results[t_idx].public_share.point,
            &ballots,
            &params,
            &mut rng,
        )
        .unwrap();
        serial_partials.push(sp);
    }

    // Phase 2: Deduplicate and sum
    let (valid_indices, vote_sums) = tally::tally_and_verify(
        &ballots,
        &serial_partials,
        &public_shares,
        &params,
        &mut rng,
    )
    .unwrap();

    assert_eq!(valid_indices.len(), 8); // All 8 ballots valid, no duplicates

    // Phase 3: Vote decryption
    let mut vote_partials: Vec<Vec<tally::VotePartialDecryption>> = Vec::new();
    for &t_idx in &active_talliers {
        let vp = tally::tally_vote_decrypt(
            &dkg_results[t_idx].key_share,
            &dkg_results[t_idx].public_share.point,
            &vote_sums,
            &params,
            &mut rng,
        )
        .unwrap();
        vote_partials.push(vp);
    }

    // Phase 4: Compute result
    let result = tally::compute_result(
        &vote_sums,
        &vote_partials,
        &public_shares,
        &params,
        valid_indices.len(),
        0,
    )
    .unwrap();

    // === Step 8: Verify Result ===
    assert_eq!(result.valid_ballot_count, 8);
    assert_eq!(result.duplicate_count, 0);
    assert_eq!(result.tally.len(), 4);

    for (choice, count) in &result.tally {
        assert_eq!(
            *count,
            expected_tally[choice.0 as usize],
            "Mismatch for choice {}: expected {}, got {}",
            choice.0,
            expected_tally[choice.0 as usize],
            count
        );
    }

    println!("Election result:");
    for (choice, count) in &result.tally {
        println!(
            "  {}: {} votes",
            params.choice_descriptions[choice.0 as usize], count
        );
    }
}

/// Test coercion resistance: voter recasts ballot, only the last one counts.
#[test]
fn coercion_resistance_ballot_recast() {
    let mut rng = OsRng;

    let config = ElectionConfig {
        election_id: ElectionId(b"coercion-test".to_vec()),
        description: "Coercion test".into(),
        num_choices: 2,
        choice_descriptions: vec!["Yes".into(), "No".into()],
        min_choices: 1,
        max_choices: 1,
        num_voters: 4,
        set_base: 2,
        set_depth: 2,
        num_talliers: 2,
        threshold: 2,
    };

    let params = params::setup_election(config);
    let g = params.generators.g;

    // DKG
    let mut polynomials = Vec::new();
    let mut round1_outputs = Vec::new();
    for alpha in 1..=params.num_talliers {
        let (poly, output) =
            protocol::dkg_round1(TallierIndex(alpha), params.threshold, &g, &mut rng);
        polynomials.push(poly);
        round1_outputs.push(output);
    }
    let mut all_round2 = Vec::new();
    for poly in &polynomials {
        all_round2.push(protocol::dkg_round2(poly, params.num_talliers));
    }
    let mut dkg_results = Vec::new();
    for alpha in 1..=params.num_talliers {
        let alpha_idx = (alpha - 1) as usize;
        let received_shares: Vec<_> = (0..params.num_talliers as usize)
            .filter(|&b| b != alpha_idx)
            .map(|b| {
                let share = all_round2[b]
                    .shares
                    .iter()
                    .find(|(idx, _)| *idx == TallierIndex(alpha))
                    .unwrap()
                    .1;
                (TallierIndex((b + 1) as u32), share)
            })
            .collect();
        dkg_results.push(
            protocol::dkg_finalize(
                TallierIndex(alpha),
                &polynomials[alpha_idx],
                &received_shares,
                &round1_outputs,
                &g,
                &mut rng,
            )
            .unwrap(),
        );
    }

    let public_shares: Vec<PublicKeyShare> =
        dkg_results.iter().map(|r| r.public_share.clone()).collect();
    let election_key = dkg_results[0].election_public_key;

    // Voters
    let mut voter_secrets = Vec::new();
    let mut voter_registrations = Vec::new();
    for i in 0..params.num_voters {
        let (secret, reg) = setup::setup_voter(VoterIndex(i), &params, &mut rng).unwrap();
        voter_secrets.push(secret);
        voter_registrations.push(reg);
    }

    let all_ballot_keys: Vec<PedersenCommitment> =
        voter_registrations.iter().map(|r| r.ballot_key).collect();

    // Voter 0 is coerced: first votes "No", then recasts as "Yes"
    let coerced_ballot = ballot::vote(
        &voter_secrets[0],
        0,
        &[false, true], // "No" under coercion
        &params,
        &election_key,
        &all_ballot_keys,
        &mut rng,
    )
    .unwrap();

    let recast_ballot = ballot::vote(
        &voter_secrets[0],
        0,
        &[true, false], // "Yes" — voter's true choice
        &params,
        &election_key,
        &all_ballot_keys,
        &mut rng,
    )
    .unwrap();

    // Other voters vote normally
    let voter1_ballot = ballot::vote(
        &voter_secrets[1],
        1,
        &[true, false], // Yes
        &params,
        &election_key,
        &all_ballot_keys,
        &mut rng,
    )
    .unwrap();

    let voter2_ballot = ballot::vote(
        &voter_secrets[2],
        2,
        &[false, true], // No
        &params,
        &election_key,
        &all_ballot_keys,
        &mut rng,
    )
    .unwrap();

    let voter3_ballot = ballot::vote(
        &voter_secrets[3],
        3,
        &[true, false], // Yes
        &params,
        &election_key,
        &all_ballot_keys,
        &mut rng,
    )
    .unwrap();

    // Bulletin board receives all ballots (coerced first, then recast)
    let ballots = vec![
        coerced_ballot,  // index 0 - coerced, should be overridden
        voter1_ballot,   // index 1
        voter2_ballot,   // index 2
        voter3_ballot,   // index 3
        recast_ballot,   // index 4 - replaces index 0 (same serial)
    ];

    // Tally
    let mut serial_partials = Vec::new();
    for t_idx in 0..2 {
        let sp = tally::tally_serial_decrypt(
            &dkg_results[t_idx].key_share,
            &dkg_results[t_idx].public_share.point,
            &ballots,
            &params,
            &mut rng,
        )
        .unwrap();
        serial_partials.push(sp);
    }

    let (valid_indices, vote_sums) = tally::tally_and_verify(
        &ballots,
        &serial_partials,
        &public_shares,
        &params,
        &mut rng,
    )
    .unwrap();

    // Should have 4 valid ballots (voter 0's coerced ballot replaced by recast)
    assert_eq!(valid_indices.len(), 4);

    let mut vote_partials = Vec::new();
    for t_idx in 0..2 {
        let vp = tally::tally_vote_decrypt(
            &dkg_results[t_idx].key_share,
            &dkg_results[t_idx].public_share.point,
            &vote_sums,
            &params,
            &mut rng,
        )
        .unwrap();
        vote_partials.push(vp);
    }

    let result = tally::compute_result(
        &vote_sums,
        &vote_partials,
        &public_shares,
        &params,
        valid_indices.len(),
        1, // 1 duplicate
    )
    .unwrap();

    // Expected: Yes=3 (voters 0-recast, 1, 3), No=1 (voter 2)
    assert_eq!(result.tally[0].1, 3, "Yes should be 3");
    assert_eq!(result.tally[1].1, 1, "No should be 1");
    assert_eq!(result.duplicate_count, 1);
}
