//! Shared code for large-scale election benchmarks (N >= 2^18).
//!
//! At these scales, creating all N ballots for a full tally is too expensive.
//! We create the voter list (ballot keys) but only benchmark single-ballot
//! operations: create, verify, and the commitment set proof in isolation.

use criterion::{Criterion, SamplingMode};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(20260412)
}

use aura::dkg::protocol;
use aura::election::ballot;
use aura::election::params::{self, ElectionConfig};
use aura::election::setup;
use aura::proofs::commitment_set::{
    CommitmentSetParams, CommitmentSetProof, CommitmentSetStatement, CommitmentSetWitness,
};
use aura::types::{ElectionId, PedersenCommitment, TallierIndex, VoterIndex};

fn run_dkg(
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

pub fn bench_ballot_only(c: &mut Criterion, n: u32, m: u32) {
    let mut rng = bench_rng();
    let num_voters = n.pow(m);
    let label = format!("N{}", num_voters);

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
    let h = params.generators.h;
    let dkg_results = run_dkg(3, 2, &g);
    let election_key = dkg_results[0].election_public_key;

    // Create voter 0's secret + all ballot keys (random commitments for the rest)
    let (voter_secret, voter_reg) =
        setup::setup_voter(VoterIndex(0), &params, &mut rng).unwrap();

    eprintln!("[{}] Generating {} voter ballot keys...", label, num_voters);
    let mut all_ballot_keys: Vec<PedersenCommitment> = Vec::with_capacity(num_voters as usize);
    all_ballot_keys.push(voter_reg.ballot_key);
    for _ in 1..num_voters {
        let s = Scalar::random(&mut rng);
        let r = Scalar::random(&mut rng);
        all_ballot_keys.push(PedersenCommitment::commit(&s, &r, &g, &h));
    }
    eprintln!("[{}] Fixture ready.", label);

    let choices = vec![true, false, true, false];

    // ── Ballot create ────────────────────────────────────────────────
    {
        let mut group = c.benchmark_group(format!("{}/ballot", label));
        group.sample_size(10);
        group.sampling_mode(SamplingMode::Flat);
        group.measurement_time(std::time::Duration::from_secs(300));
        group.warm_up_time(std::time::Duration::from_secs(10));
        group.noise_threshold(0.05);
        group.significance_level(0.01);

        group.bench_function("create", |b| {
            let mut rng = bench_rng();
            b.iter(|| {
                ballot::vote(
                    &voter_secret,
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
            &voter_secret,
            0,
            &choices,
            &params,
            &election_key,
            &all_ballot_keys,
            &mut rng,
        )
        .unwrap();

        group.bench_function("verify", |b| {
            b.iter(|| {
                ballot::verify_ballot(&test_ballot, &params, &election_key, &all_ballot_keys)
                    .unwrap()
            })
        });

        group.finish();
    }

    // ── Commitment set proof in isolation ─────────────────────────────
    {
        let all_points: Vec<RistrettoPoint> =
            all_ballot_keys.iter().map(|c| *c.point()).collect();
        let blinding = Scalar::random(&mut rng);
        let c_prime = all_points[0] - blinding * h;

        let set_params = CommitmentSetParams { n, m, g, h };
        let statement = CommitmentSetStatement {
            params: set_params,
            commitments: all_points,
            c_prime,
        };
        let witness = CommitmentSetWitness {
            index: 0,
            blinding,
        };

        let mut group = c.benchmark_group(format!("{}/set_proof", label));
        group.sample_size(10);
        group.sampling_mode(SamplingMode::Flat);
        group.measurement_time(std::time::Duration::from_secs(300));
        group.warm_up_time(std::time::Duration::from_secs(10));
        group.noise_threshold(0.05);
        group.significance_level(0.01);

        group.bench_function("prove", |b| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                CommitmentSetProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });

        let mut t = Transcript::new(b"bench");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut t, &mut rng).unwrap();

        group.bench_function("verify", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });

        group.finish();
    }
}
