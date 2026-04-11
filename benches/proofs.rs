use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand::rngs::OsRng;

use aura::proofs::bit_vector::{BitVectorProof, BitVectorStatement, BitVectorWitness};
use aura::proofs::commitment_set::{
    CommitmentSetParams, CommitmentSetProof, CommitmentSetStatement, CommitmentSetWitness,
};
use aura::proofs::dleq::{DleqProof, DleqStatement, DleqWitness};
use aura::proofs::encryption_validity::{
    EncValStatement, EncValWitness, EncryptionValidityProof,
};
use aura::proofs::representation::{
    RepresentationProof, RepresentationStatement, RepresentationWitness,
};
use aura::proofs::serial_validity::{SerValStatement, SerValWitness, SerialValidityProof};

// ─── Individual Proof Costs (Table 1 in thesis) ───────────────────────────

fn bench_all_proofs_individual(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("individual_proofs");
    group.sample_size(100);

    // --- Representation proof (2 generators, typical for voter setup) ---
    {
        let generators: Vec<RistrettoPoint> =
            (0..2).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let scalars: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
        let target = RistrettoPoint::multiscalar_mul(&scalars, &generators);
        let statement = RepresentationStatement {
            generators: generators.clone(),
            target,
        };
        let witness = RepresentationWitness {
            scalars: scalars.clone(),
        };

        group.bench_function("rep_prove", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                RepresentationProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });
        let mut pt = Transcript::new(b"bench");
        let proof = RepresentationProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        group.bench_function("rep_verify", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });
    }

    // --- DLEQ proof ---
    {
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);
        let y_scalar = Scalar::random(&mut rng);
        let statement = DleqStatement {
            g,
            h,
            y: y_scalar * g,
            y_prime: y_scalar * h,
        };
        let witness = DleqWitness { scalar: y_scalar };

        group.bench_function("dleq_prove", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                DleqProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });
        let mut pt = Transcript::new(b"bench");
        let proof = DleqProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        group.bench_function("dleq_verify", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });
    }

    // --- Encryption validity proof ---
    {
        let g = RistrettoPoint::random(&mut rng);
        let h_i = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let y = sk * g;
        let r = Scalar::random(&mut rng);
        let m = Scalar::ONE;
        let statement = EncValStatement {
            g,
            y,
            h_i,
            d: r * g,
            e: r * y + m * h_i,
        };
        let witness = EncValWitness { r, m };

        group.bench_function("encval_prove", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                EncryptionValidityProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });
        let mut pt = Transcript::new(b"bench");
        let proof =
            EncryptionValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        group.bench_function("encval_verify", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });
    }

    // --- Serial validity proof ---
    {
        let f = RistrettoPoint::random(&mut rng);
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);
        let sk = Scalar::random(&mut rng);
        let y = sk * g;
        let s = Scalar::random(&mut rng);
        let r_prime = Scalar::random(&mut rng);
        let r_double_prime = Scalar::random(&mut rng);
        let statement = SerValStatement {
            f,
            g,
            h,
            y,
            c_prime: s * g + r_prime * h,
            d_prime: r_double_prime * g,
            e_prime: s * f + r_double_prime * y,
        };
        let witness = SerValWitness {
            s,
            r_prime,
            r_double_prime,
        };

        group.bench_function("serval_prove", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                SerialValidityProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });
        let mut pt = Transcript::new(b"bench");
        let proof =
            SerialValidityProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();
        group.bench_function("serval_verify", |b| {
            b.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });
    }

    group.finish();
}

// ─── Bit Vector Proof Scaling (Figure: k' vs time) ───────────────────────

fn bench_bit_vector_scaling(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("bit_vector_scaling");
    group.sample_size(50);

    for k in [4, 8, 12, 16, 24, 32, 48, 64] {
        let generators: Vec<RistrettoPoint> =
            (0..k).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let h = RistrettoPoint::random(&mut rng);
        let w = 3u32.min(k as u32);
        let mut bits = vec![Scalar::ZERO; k];
        for i in 0..w as usize {
            bits[i] = Scalar::ONE;
        }
        let blinding = Scalar::random(&mut rng);
        let mut scalars = vec![blinding];
        let mut points = vec![h];
        for (bi, gi) in bits.iter().zip(generators.iter()) {
            scalars.push(*bi);
            points.push(*gi);
        }
        let b_point = RistrettoPoint::multiscalar_mul(&scalars, &points);

        let statement = BitVectorStatement {
            generators: generators.clone(),
            h,
            b: b_point,
            w,
        };
        let witness = BitVectorWitness {
            bits: bits.clone(),
            blinding,
        };

        group.throughput(Throughput::Elements(k as u64));

        group.bench_with_input(BenchmarkId::new("prove", k), &k, |bench, _| {
            bench.iter(|| {
                let mut t = Transcript::new(b"bench");
                BitVectorProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });

        let mut pt = Transcript::new(b"bench");
        let proof = BitVectorProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", k), &k, |bench, _| {
            bench.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

// ─── Commitment Set Proof Scaling (Figure: N_voters vs time) ─────────────

fn bench_commitment_set_scaling(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("commitment_set_scaling");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(std::time::Duration::from_secs(300));

    // (n, m) → N = n^m
    // Scales from 4 to 1,048,576 (2^20)
    let configs: Vec<(u32, u32, &str)> = vec![
        (2, 2, "N=4"),
        (2, 4, "N=16"),
        (2, 6, "N=64"),
        (2, 8, "N=256"),
        (2, 10, "N=1024"),
        (2, 12, "N=4096"),
        (2, 14, "N=16384"),
        (2, 16, "N=65536"),
        (2, 18, "N=262144"),
        (2, 20, "N=1048576"),
    ];

    for (n, m, label) in &configs {
        let big_n = (*n as usize).pow(*m);
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);

        let commitments: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| {
                let s = Scalar::random(&mut rng);
                let r = Scalar::random(&mut rng);
                s * g + r * h
            })
            .collect();

        let secret_index = big_n / 2;
        let blinding = Scalar::random(&mut rng);
        let c_prime = commitments[secret_index] - blinding * h;

        let params = CommitmentSetParams {
            n: *n,
            m: *m,
            g,
            h,
        };
        let statement = CommitmentSetStatement {
            params,
            commitments,
            c_prime,
        };
        let witness = CommitmentSetWitness {
            index: secret_index as u32,
            blinding,
        };

        group.throughput(Throughput::Elements(big_n as u64));

        group.bench_with_input(BenchmarkId::new("prove", label), label, |bench, _| {
            bench.iter(|| {
                let mut t = Transcript::new(b"bench");
                CommitmentSetProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });

        let mut pt = Transcript::new(b"bench");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", label), label, |bench, _| {
            bench.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

// ─── Batch Verification Scaling (Figure: batch size vs amortized cost) ───

fn bench_batch_verification(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("batch_verification");
    group.sample_size(20);

    for batch_size in [1, 5, 10, 25, 50, 100] {
        // Representation proofs
        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        for _ in 0..batch_size {
            let generators: Vec<RistrettoPoint> =
                (0..2).map(|_| RistrettoPoint::random(&mut rng)).collect();
            let scalars: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
            let target = RistrettoPoint::multiscalar_mul(&scalars, &generators);
            let statement = RepresentationStatement { generators, target };
            let witness = RepresentationWitness { scalars };
            let mut t = Transcript::new(b"bench");
            let proof = RepresentationProof::prove(&statement, &witness, &mut t, &mut rng).unwrap();
            proofs.push(proof);
            statements.push(statement);
        }

        group.throughput(Throughput::Elements(batch_size as u64));

        // Individual verification
        group.bench_with_input(
            BenchmarkId::new("rep_individual", batch_size),
            &batch_size,
            |bench, _| {
                bench.iter(|| {
                    for (proof, statement) in proofs.iter().zip(statements.iter()) {
                        let mut t = Transcript::new(b"bench");
                        proof.verify(statement, &mut t).unwrap();
                    }
                })
            },
        );

        // Batch verification
        group.bench_with_input(
            BenchmarkId::new("rep_batch", batch_size),
            &batch_size,
            |bench, _| {
                bench.iter(|| {
                    let mut transcripts: Vec<Transcript> =
                        (0..batch_size).map(|_| Transcript::new(b"bench")).collect();
                    RepresentationProof::batch_verify(
                        &proofs,
                        &statements,
                        &mut transcripts,
                        &mut rng,
                    )
                    .unwrap();
                })
            },
        );
    }
    group.finish();
}

// ─── Commitment Set: n-base Comparison (Table: n=2 vs n=4) ──────────────

fn bench_commitment_set_base_comparison(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("set_proof_base_comparison");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    // Compare n=2 vs n=4 for similar N
    let configs: Vec<(u32, u32, &str)> = vec![
        (2, 6, "n=2,N=64"),
        (4, 3, "n=4,N=64"),
        (2, 8, "n=2,N=256"),
        (4, 4, "n=4,N=256"),
        (2, 12, "n=2,N=4096"),
        (4, 6, "n=4,N=4096"),
        (2, 16, "n=2,N=65536"),
        (4, 8, "n=4,N=65536"),
    ];

    for (n, m, label) in &configs {
        let big_n = (*n as usize).pow(*m);
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);

        let commitments: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| {
                let s = Scalar::random(&mut rng);
                let r = Scalar::random(&mut rng);
                s * g + r * h
            })
            .collect();

        let secret_index = big_n / 3;
        let blinding = Scalar::random(&mut rng);
        let c_prime = commitments[secret_index] - blinding * h;

        let params = CommitmentSetParams {
            n: *n,
            m: *m,
            g,
            h,
        };
        let statement = CommitmentSetStatement {
            params,
            commitments,
            c_prime,
        };
        let witness = CommitmentSetWitness {
            index: secret_index as u32,
            blinding,
        };

        group.bench_with_input(BenchmarkId::new("prove", label), label, |bench, _| {
            bench.iter(|| {
                let mut t = Transcript::new(b"bench");
                CommitmentSetProof::prove(&statement, &witness, &mut t, &mut rng).unwrap()
            })
        });

        let mut pt = Transcript::new(b"bench");
        let proof = CommitmentSetProof::prove(&statement, &witness, &mut pt, &mut rng).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", label), label, |bench, _| {
            bench.iter(|| {
                let mut t = Transcript::new(b"bench");
                proof.verify(&statement, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_all_proofs_individual,
    bench_bit_vector_scaling,
    bench_commitment_set_scaling,
    bench_batch_verification,
    bench_commitment_set_base_comparison,
);
criterion_main!(benches);
