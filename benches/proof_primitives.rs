//! Benchmark suite: individual proof primitive costs.
//!
//! Measures prove and verify time for each of the 6 proof types,
//! plus batch verification scaling for representation proofs.

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode,
};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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

/// Deterministic RNG for reproducible, low-noise benchmarks.
/// Avoids OsRng syscall jitter while remaining cryptographically valid.
fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(20260412)
}

// ── Fast proofs: ~50-200 us each ────────────────────────────────────────
// Config: 200 samples, 10s measurement, 3s warmup

fn bench_representation(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("representation");
    group.sample_size(200);
    group.measurement_time(std::time::Duration::from_secs(10));
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.noise_threshold(0.03); // ignore < 3% changes
    group.significance_level(0.01);
    group.confidence_level(0.99);

    for n in [1, 2, 4, 8] {
        let gens: Vec<RistrettoPoint> = (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let scs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let target = RistrettoPoint::multiscalar_mul(&scs, &gens);
        let st = RepresentationStatement { generators: gens, target };
        let wi = RepresentationWitness { scalars: scs };

        group.bench_with_input(BenchmarkId::new("prove", n), &n, |b, _| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                RepresentationProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
            })
        });

        let mut t = Transcript::new(b"b");
        let pr = RepresentationProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", n), &n, |b, _| {
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                pr.verify(&st, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

fn bench_dleq(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("dleq");
    group.sample_size(200);
    group.measurement_time(std::time::Duration::from_secs(10));
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.noise_threshold(0.03);
    group.significance_level(0.01);
    group.confidence_level(0.99);

    let g = RistrettoPoint::random(&mut rng);
    let h = RistrettoPoint::random(&mut rng);
    let y = Scalar::random(&mut rng);
    let st = DleqStatement { g, h, y: y * g, y_prime: y * h };
    let wi = DleqWitness { scalar: y };

    group.bench_function("prove", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            DleqProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
        })
    });

    let mut t = Transcript::new(b"b");
    let pr = DleqProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr.verify(&st, &mut t).unwrap()
        })
    });
    group.finish();
}

fn bench_encryption_validity(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("enc_validity");
    group.sample_size(200);
    group.measurement_time(std::time::Duration::from_secs(10));
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.noise_threshold(0.03);
    group.significance_level(0.01);
    group.confidence_level(0.99);

    let g = RistrettoPoint::random(&mut rng);
    let hi = RistrettoPoint::random(&mut rng);
    let sk = Scalar::random(&mut rng);
    let y = sk * g;
    let r = Scalar::random(&mut rng);
    let m = Scalar::ONE;
    let st = EncValStatement { g, y, h_i: hi, d: r * g, e: r * y + m * hi };
    let wi = EncValWitness { r, m };

    group.bench_function("prove", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            EncryptionValidityProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
        })
    });

    let mut t = Transcript::new(b"b");
    let pr = EncryptionValidityProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr.verify(&st, &mut t).unwrap()
        })
    });
    group.finish();
}

fn bench_serial_validity(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("serial_validity");
    group.sample_size(200);
    group.measurement_time(std::time::Duration::from_secs(10));
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.noise_threshold(0.03);
    group.significance_level(0.01);
    group.confidence_level(0.99);

    let f = RistrettoPoint::random(&mut rng);
    let g = RistrettoPoint::random(&mut rng);
    let h = RistrettoPoint::random(&mut rng);
    let sk = Scalar::random(&mut rng);
    let y = sk * g;
    let s = Scalar::random(&mut rng);
    let rp = Scalar::random(&mut rng);
    let rdp = Scalar::random(&mut rng);
    let st = SerValStatement {
        f, g, h, y,
        c_prime: s * g + rp * h,
        d_prime: rdp * g,
        e_prime: s * f + rdp * y,
    };
    let wi = SerValWitness { s, r_prime: rp, r_double_prime: rdp };

    group.bench_function("prove", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            SerialValidityProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
        })
    });

    let mut t = Transcript::new(b"b");
    let pr = SerialValidityProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr.verify(&st, &mut t).unwrap()
        })
    });
    group.finish();
}

// ── Medium proofs: ~0.3-2 ms each ──────────────────────────────────────
// Config: 100 samples, 15s measurement, 3s warmup

fn bench_bit_vector(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("bit_vector");
    group.sample_size(100);
    group.measurement_time(std::time::Duration::from_secs(15));
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.noise_threshold(0.03);
    group.significance_level(0.01);
    group.confidence_level(0.99);

    for k in [4, 5, 8, 12, 16, 24, 32, 48, 64] {
        let gens: Vec<RistrettoPoint> = (0..k).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let h = RistrettoPoint::random(&mut rng);
        let w = 2u32.min(k as u32);
        let mut bits = vec![Scalar::ZERO; k];
        for i in 0..w as usize {
            bits[i] = Scalar::ONE;
        }
        let bl = Scalar::random(&mut rng);
        let mut sc = vec![bl];
        let mut pt = vec![h];
        for (bi, gi) in bits.iter().zip(gens.iter()) {
            sc.push(*bi);
            pt.push(*gi);
        }
        let bp = RistrettoPoint::multiscalar_mul(&sc, &pt);
        let st = BitVectorStatement { generators: gens, h, b: bp, w };
        let wi = BitVectorWitness { bits, blinding: bl };

        group.bench_with_input(BenchmarkId::new("prove", k), &k, |b, _| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                BitVectorProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
            })
        });

        let mut t = Transcript::new(b"b");
        let pr = BitVectorProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", k), &k, |b, _| {
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                pr.verify(&st, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

// ── Slow proofs: ~1-100+ ms each ───────────────────────────────────────
// Config: 20 samples, flat mode, 60s measurement, 5s warmup

fn bench_commitment_set(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("commitment_set");
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);
    group.measurement_time(std::time::Duration::from_secs(120));
    group.warm_up_time(std::time::Duration::from_secs(5));
    group.noise_threshold(0.05); // 5% threshold for slow ops
    group.significance_level(0.01);
    group.confidence_level(0.99);

    for (n, m, label) in [
        (2u32, 2u32, "N=4"),
        (2, 4, "N=16"),
        (2, 6, "N=64"),
        (2, 8, "N=256"),
        (2, 10, "N=1024"),
        (2, 12, "N=4096"),
        (4, 3, "N=64_n4"),
        (4, 4, "N=256_n4"),
        (4, 5, "N=1024_n4"),
    ] {
        let big_n = (n as usize).pow(m);
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);
        let comms: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| Scalar::random(&mut rng) * g + Scalar::random(&mut rng) * h)
            .collect();
        let idx = (big_n / 2) as u32;
        let bl = Scalar::random(&mut rng);
        let cp = comms[idx as usize] - bl * h;
        let params = CommitmentSetParams { n, m, g, h };
        let st = CommitmentSetStatement { params, commitments: comms, c_prime: cp };
        let wi = CommitmentSetWitness { index: idx, blinding: bl };

        group.bench_with_input(BenchmarkId::new("prove", label), &label, |b, _| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                CommitmentSetProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
            })
        });

        let mut t = Transcript::new(b"b");
        let pr = CommitmentSetProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", label), &label, |b, _| {
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                pr.verify(&st, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

// ── Batch verification amortization ─────────────────────────────────────

fn bench_batch_verify(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("batch_verify_rep");
    group.sample_size(50);
    group.measurement_time(std::time::Duration::from_secs(15));
    group.warm_up_time(std::time::Duration::from_secs(3));
    group.noise_threshold(0.03);
    group.significance_level(0.01);
    group.confidence_level(0.99);

    for batch in [1, 10, 25, 50, 100] {
        let mut proofs = Vec::new();
        let mut statements = Vec::new();
        for _ in 0..batch {
            let gens: Vec<RistrettoPoint> =
                (0..2).map(|_| RistrettoPoint::random(&mut rng)).collect();
            let scs: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
            let target = RistrettoPoint::multiscalar_mul(&scs, &gens);
            let st = RepresentationStatement { generators: gens, target };
            let wi = RepresentationWitness { scalars: scs };
            let mut t = Transcript::new(b"b");
            proofs.push(RepresentationProof::prove(&st, &wi, &mut t, &mut rng).unwrap());
            statements.push(st);
        }

        group.bench_with_input(BenchmarkId::new("individual", batch), &batch, |b, _| {
            b.iter(|| {
                for (pr, st) in proofs.iter().zip(statements.iter()) {
                    let mut t = Transcript::new(b"b");
                    pr.verify(st, &mut t).unwrap();
                }
            })
        });
        group.bench_with_input(BenchmarkId::new("batch", batch), &batch, |b, _| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut ts: Vec<Transcript> =
                    (0..batch).map(|_| Transcript::new(b"b")).collect();
                RepresentationProof::batch_verify(&proofs, &statements, &mut ts, &mut rng)
                    .unwrap();
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_representation,
    bench_dleq,
    bench_encryption_validity,
    bench_serial_validity,
    bench_bit_vector,
    bench_commitment_set,
    bench_batch_verify,
);
criterion_main!(benches);
