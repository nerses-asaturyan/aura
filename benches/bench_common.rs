//! Shared code for election benchmark suites (N <= 65536).
//! Included via `#[path]` in each election_nXXX.rs file.

use criterion::{BenchmarkId, Criterion, SamplingMode};
use curve25519_dalek::ristretto::RistrettoPoint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use aura::dkg::protocol;
use aura::election::ballot;
use aura::election::params::{self, ElectionConfig, ElectionParams};
use aura::election::setup::{self, VoterSecret};
use aura::election::tally;
use aura::elgamal::keys::PublicKeyShare;
use aura::types::{ElectionId, PedersenCommitment, TallierIndex, VoterIndex};

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(20260412)
}

pub fn run_dkg(
    num_talliers: u32,
    threshold: u32,
    g: &RistrettoPoint,
) -> Vec<protocol::DkgResult> {
    let mut rng = bench_rng();
    let mut polys = Vec::new();
    let mut r1 = Vec::new();
    for alpha in 1..=num_talliers {
        let (p, o) = protocol::dkg_round1(TallierIndex(alpha), threshold, g, &mut rng);
        polys.push(p);
        r1.push(o);
    }
    let mut r2 = Vec::new();
    for p in &polys {
        r2.push(protocol::dkg_round2(p, num_talliers));
    }
    let mut results = Vec::new();
    for alpha in 1..=num_talliers {
        let idx = (alpha - 1) as usize;
        let received: Vec<_> = (0..num_talliers as usize)
            .filter(|&b| b != idx)
            .map(|b| {
                let s = r2[b]
                    .shares
                    .iter()
                    .find(|(i, _)| *i == TallierIndex(alpha))
                    .unwrap()
                    .1;
                (TallierIndex((b + 1) as u32), s)
            })
            .collect();
        results.push(
            protocol::dkg_finalize(
                TallierIndex(alpha),
                &polys[idx],
                &received,
                &r1,
                g,
                &mut rng,
            )
            .unwrap(),
        );
    }
    results
}

pub struct ElectionFixture {
    pub params: ElectionParams,
    pub dkg_results: Vec<protocol::DkgResult>,
    pub public_shares: Vec<PublicKeyShare>,
    pub voter_secrets: Vec<VoterSecret>,
    pub all_ballot_keys: Vec<PedersenCommitment>,
    pub ballots: Vec<ballot::Ballot>,
}

pub fn setup_election(n: u32, m: u32) -> ElectionFixture {
    let mut rng = bench_rng();
    let num_voters = n.pow(m);

    let config = ElectionConfig {
        election_id: ElectionId(format!("bench-{}", num_voters).into_bytes()),
        description: format!("{} voter benchmark", num_voters),
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
        ballots.push(
            ballot::vote(
                &voter_secrets[i],
                i as u32,
                &choices,
                &params,
                &election_key,
                &all_ballot_keys,
                &mut rng,
            )
            .unwrap(),
        );
    }

    ElectionFixture {
        params,
        dkg_results,
        public_shares,
        voter_secrets,
        all_ballot_keys,
        ballots,
    }
}

pub fn bench_election_suite(c: &mut Criterion, n: u32, m: u32) {
    let num_voters = n.pow(m);
    let label = format!("N{}", num_voters);

    let fixture = setup_election(n, m);
    let election_key = fixture.dkg_results[0].election_public_key;

    // ── DKG (fast, ~1-2 ms) ─────────────────────────────────────────
    {
        let g = fixture.params.generators.g;
        let mut group = c.benchmark_group(format!("{}/dkg", label));
        group.sample_size(100);
        group.measurement_time(std::time::Duration::from_secs(10));
        group.warm_up_time(std::time::Duration::from_secs(2));
        group.noise_threshold(0.03);
        group.significance_level(0.01);

        group.bench_function("2of3", |b| {
            b.iter(|| run_dkg(3, 2, &g))
        });
        group.finish();
    }

    // ── Voter registration (fast, ~150 us) ──────────────────────────
    {
        let mut group = c.benchmark_group(format!("{}/voter", label));
        group.sample_size(200);
        group.measurement_time(std::time::Duration::from_secs(10));
        group.warm_up_time(std::time::Duration::from_secs(2));
        group.noise_threshold(0.03);
        group.significance_level(0.01);

        group.bench_function("registration", |b| {
            let mut rng = bench_rng();
            b.iter(|| setup::setup_voter(VoterIndex(0), &fixture.params, &mut rng).unwrap())
        });
        group.finish();
    }

    // ── Single ballot create & verify (medium, ~2-100 ms) ───────────
    {
        let choices = vec![true, false, true, false];

        let mut group = c.benchmark_group(format!("{}/ballot", label));
        group.sample_size(50);
        group.measurement_time(std::time::Duration::from_secs(20));
        group.warm_up_time(std::time::Duration::from_secs(3));
        group.noise_threshold(0.03);
        group.significance_level(0.01);

        group.bench_function("create", |b| {
            let mut rng = bench_rng();
            b.iter(|| {
                ballot::vote(
                    &fixture.voter_secrets[0],
                    0,
                    &choices,
                    &fixture.params,
                    &election_key,
                    &fixture.all_ballot_keys,
                    &mut rng,
                )
                .unwrap()
            })
        });

        group.bench_function("verify", |b| {
            b.iter(|| {
                ballot::verify_ballot(
                    &fixture.ballots[0],
                    &fixture.params,
                    &election_key,
                    &fixture.all_ballot_keys,
                )
                .unwrap()
            })
        });
        group.finish();
    }

    // ── Ballot verification batch (slow, ~2-250 ms) ─────────────────
    {
        let mut group = c.benchmark_group(format!("{}/verify_batch", label));
        group.sample_size(10);
        group.sampling_mode(SamplingMode::Flat);
        group.measurement_time(std::time::Duration::from_secs(30));
        group.warm_up_time(std::time::Duration::from_secs(3));
        group.noise_threshold(0.05);
        group.significance_level(0.01);

        let batch_sizes: Vec<usize> = [1, 10, 50, 100]
            .iter()
            .copied()
            .filter(|&s| s <= num_voters as usize)
            .collect();

        for count in batch_sizes {
            group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
                b.iter(|| {
                    for bl in fixture.ballots.iter().take(count) {
                        ballot::verify_ballot(
                            bl,
                            &fixture.params,
                            &election_key,
                            &fixture.all_ballot_keys,
                        )
                        .unwrap();
                    }
                })
            });
        }
        group.finish();
    }

    // ── Tally (slow, ~5 ms - 10+ s) ────────────────────────────────
    {
        let mut group = c.benchmark_group(format!("{}/tally", label));
        group.sample_size(10);
        group.sampling_mode(SamplingMode::Flat);
        group.measurement_time(std::time::Duration::from_secs(60));
        group.warm_up_time(std::time::Duration::from_secs(5));
        group.noise_threshold(0.05);
        group.significance_level(0.01);

        group.bench_function("serial_decrypt_per_tallier", |b| {
            let mut rng = bench_rng();
            b.iter(|| {
                tally::tally_serial_decrypt(
                    &fixture.dkg_results[0].key_share,
                    &fixture.dkg_results[0].public_share.point,
                    &fixture.ballots,
                    &fixture.params,
                    &mut rng,
                )
                .unwrap()
            })
        });

        group.bench_function("full_pipeline", |b| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut sp = Vec::new();
                for t in 0..2 {
                    sp.push(
                        tally::tally_serial_decrypt(
                            &fixture.dkg_results[t].key_share,
                            &fixture.dkg_results[t].public_share.point,
                            &fixture.ballots,
                            &fixture.params,
                            &mut rng,
                        )
                        .unwrap(),
                    );
                }
                let (vi, vs) = tally::tally_and_verify(
                    &fixture.ballots,
                    &sp,
                    &fixture.public_shares,
                    &fixture.params,
                    &mut rng,
                )
                .unwrap();
                let mut vp = Vec::new();
                for t in 0..2 {
                    vp.push(
                        tally::tally_vote_decrypt(
                            &fixture.dkg_results[t].key_share,
                            &fixture.dkg_results[t].public_share.point,
                            &vs,
                            &fixture.params,
                            &mut rng,
                        )
                        .unwrap(),
                    );
                }
                tally::compute_result(
                    &vs,
                    &vp,
                    &fixture.public_shares,
                    &fixture.params,
                    vi.len(),
                    0,
                )
                .unwrap()
            })
        });

        group.finish();
    }
}
