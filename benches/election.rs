use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::rngs::OsRng;

use aura::dkg::protocol::{self, DkgRound2Output};
use aura::election::ballot;
use aura::election::params::{self, ElectionConfig};
use aura::election::setup;
use aura::election::tally;
use aura::elgamal::keys::PublicKeyShare;
use aura::types::{ElectionId, PedersenCommitment, TallierIndex, VoterIndex};

/// Helper: run a full DKG.
fn run_dkg(
    num_talliers: u32,
    threshold: u32,
    g: &RistrettoPoint,
) -> Vec<protocol::DkgResult> {
    let mut rng = OsRng;
    let mut polynomials = Vec::new();
    let mut round1_outputs = Vec::new();
    for alpha in 1..=num_talliers {
        let (poly, output) = protocol::dkg_round1(TallierIndex(alpha), threshold, g, &mut rng);
        polynomials.push(poly);
        round1_outputs.push(output);
    }
    let mut all_round2 = Vec::new();
    for poly in &polynomials {
        all_round2.push(protocol::dkg_round2(poly, num_talliers));
    }
    let mut results = Vec::new();
    for alpha in 1..=num_talliers {
        let idx = (alpha - 1) as usize;
        let received: Vec<_> = (0..num_talliers as usize)
            .filter(|&b| b != idx)
            .map(|b| {
                let share = all_round2[b]
                    .shares
                    .iter()
                    .find(|(i, _)| *i == TallierIndex(alpha))
                    .unwrap()
                    .1;
                (TallierIndex((b + 1) as u32), share)
            })
            .collect();
        results.push(
            protocol::dkg_finalize(
                TallierIndex(alpha),
                &polynomials[idx],
                &received,
                &round1_outputs,
                g,
                &mut rng,
            )
            .unwrap(),
        );
    }
    results
}

// ─── DKG Scaling (Table: tallier count vs time) ──────────────────────────

fn bench_dkg_scaling(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("dkg_scaling");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for (num_talliers, threshold) in [(2, 2), (3, 2), (5, 3), (7, 4), (10, 6)] {
        let g = RistrettoPoint::random(&mut rng);

        group.bench_with_input(
            BenchmarkId::new("full_dkg", format!("{}-of-{}", threshold, num_talliers)),
            &num_talliers,
            |bench, _| {
                bench.iter(|| run_dkg(num_talliers, threshold, &g))
            },
        );
    }
    group.finish();
}

// ─── Ballot Creation Scaling (Figure: N_voters vs ballot create/verify) ──

fn bench_ballot_scaling(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("ballot_scaling");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(std::time::Duration::from_secs(300));

    // Ballot scaling from N=4 to N=2^20
    for (n, m) in [
        (2u32, 2u32),
        (2, 4),
        (2, 6),
        (2, 8),
        (2, 10),
        (2, 12),
        (2, 14),
        (2, 16),
        (2, 18),
        (2, 20),
    ] {
        let num_voters = n.pow(m);
        let label = format!("N={}", num_voters);

        let config = ElectionConfig {
            election_id: ElectionId(format!("bench-{}", num_voters).into_bytes()),
            description: "Benchmark".into(),
            num_choices: 4,
            choice_descriptions: vec!["A".into(), "B".into(), "C".into(), "D".into()],
            min_choices: 1,
            max_choices: 2,
            num_voters,
            set_base: n,
            set_depth: m,
            num_talliers: 3,
            threshold: 2,
        };

        let params = params::setup_election(config);
        let g = params.generators.g;
        let dkg_results = run_dkg(3, 2, &g);
        let election_key = dkg_results[0].election_public_key;

        let mut voter_secrets = Vec::new();
        let mut voter_registrations = Vec::new();
        for i in 0..num_voters {
            let (secret, reg) = setup::setup_voter(VoterIndex(i), &params, &mut rng).unwrap();
            voter_secrets.push(secret);
            voter_registrations.push(reg);
        }
        let all_ballot_keys: Vec<PedersenCommitment> =
            voter_registrations.iter().map(|r| r.ballot_key).collect();

        let choices = vec![true, false, true, false];

        group.throughput(Throughput::Elements(num_voters as u64));

        group.bench_with_input(BenchmarkId::new("vote", &label), &label, |bench, _| {
            bench.iter(|| {
                ballot::vote(
                    &voter_secrets[0],
                    0,
                    &choices,
                    &params,
                    &election_key,
                    &all_ballot_keys,
                    &mut rng,
                )
                .unwrap()
            })
        });

        let test_ballot = ballot::vote(
            &voter_secrets[0],
            0,
            &choices,
            &params,
            &election_key,
            &all_ballot_keys,
            &mut rng,
        )
        .unwrap();

        group.bench_with_input(BenchmarkId::new("verify_ballot", &label), &label, |bench, _| {
            bench.iter(|| {
                ballot::verify_ballot(&test_ballot, &params, &election_key, &all_ballot_keys)
                    .unwrap()
            })
        });
    }
    group.finish();
}

// ─── End-to-End Tally Scaling (Figure: voter count vs tally time) ────────

fn bench_tally_scaling(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("tally_scaling");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    for (n, m) in [(2u32, 3u32), (2, 4), (2, 6), (2, 8), (2, 10)] {
        let num_voters = n.pow(m);
        let label = format!("N={}", num_voters);

        let config = ElectionConfig {
            election_id: ElectionId(format!("bench-tally-{}", num_voters).into_bytes()),
            description: "Tally bench".into(),
            num_choices: 4,
            choice_descriptions: vec!["A".into(), "B".into(), "C".into(), "D".into()],
            min_choices: 1,
            max_choices: 2,
            num_voters,
            set_base: n,
            set_depth: m,
            num_talliers: 3,
            threshold: 2,
        };

        let params = params::setup_election(config);
        let g = params.generators.g;
        let dkg_results = run_dkg(3, 2, &g);
        let election_key = dkg_results[0].election_public_key;
        let public_shares: Vec<PublicKeyShare> =
            dkg_results.iter().map(|r| r.public_share.clone()).collect();

        let mut voter_secrets = Vec::new();
        let mut voter_registrations = Vec::new();
        for i in 0..num_voters {
            let (secret, reg) = setup::setup_voter(VoterIndex(i), &params, &mut rng).unwrap();
            voter_secrets.push(secret);
            voter_registrations.push(reg);
        }
        let all_ballot_keys: Vec<PedersenCommitment> =
            voter_registrations.iter().map(|r| r.ballot_key).collect();

        let mut ballots = Vec::new();
        for i in 0..num_voters as usize {
            let choices = if i % 2 == 0 {
                vec![true, false, true, false]
            } else {
                vec![false, true, false, false]
            };
            let b = ballot::vote(
                &voter_secrets[i],
                i as u32,
                &choices,
                &params,
                &election_key,
                &all_ballot_keys,
                &mut rng,
            )
            .unwrap();
            ballots.push(b);
        }

        group.throughput(Throughput::Elements(num_voters as u64));

        // Benchmark serial decryption (per-tallier)
        group.bench_with_input(
            BenchmarkId::new("serial_decrypt_per_tallier", &label),
            &label,
            |bench, _| {
                bench.iter(|| {
                    tally::tally_serial_decrypt(
                        &dkg_results[0].key_share,
                        &dkg_results[0].public_share.point,
                        &ballots,
                        &params,
                        &mut rng,
                    )
                    .unwrap()
                })
            },
        );

        // Benchmark full tally pipeline
        group.bench_with_input(
            BenchmarkId::new("full_tally", &label),
            &label,
            |bench, _| {
                bench.iter(|| {
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

                    tally::compute_result(
                        &vote_sums,
                        &vote_partials,
                        &public_shares,
                        &params,
                        valid_indices.len(),
                        0,
                    )
                    .unwrap()
                })
            },
        );
    }
    group.finish();
}

// ─── Voter Registration Scaling ──────────────────────────────────────────

fn bench_voter_setup(c: &mut Criterion) {
    let mut rng = OsRng;
    let config = ElectionConfig {
        election_id: ElectionId(b"bench-setup".to_vec()),
        description: "Setup bench".into(),
        num_choices: 4,
        choice_descriptions: vec!["A".into(), "B".into(), "C".into(), "D".into()],
        min_choices: 1,
        max_choices: 2,
        num_voters: 8,
        set_base: 2,
        set_depth: 3,
        num_talliers: 3,
        threshold: 2,
    };
    let params = params::setup_election(config);

    c.bench_function("voter_registration", |b| {
        b.iter(|| setup::setup_voter(VoterIndex(0), &params, &mut rng).unwrap())
    });
}

criterion_group!(
    benches,
    bench_dkg_scaling,
    bench_ballot_scaling,
    bench_tally_scaling,
    bench_voter_setup,
);
criterion_main!(benches);
