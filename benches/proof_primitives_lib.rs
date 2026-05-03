//! Benchmark suite: library-backed proof primitives, side-by-side with the
//! hand-rolled paper-faithful implementations under `aura::proofs::*`.
//!
//! Run with:
//!     cargo bench --bench proof_primitives_lib --features lib-proofs
//!
//! Each proof type produces two `BenchmarkId` columns within a single
//! Criterion group:
//!   - `prove/handrolled`, `prove/lib`
//!   - `verify/handrolled`, `verify/lib`
//!
//! Statement-fidelity caveats per proof are documented in the corresponding
//! `aura::proofs::lib_backed::*` module docstrings — the lib-backed
//! bit-vector and commitment-set proofs do not bind to the same statement
//! as the hand-rolled versions, so cross-mode comparison is timing-only.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use aura::proofs::bit_vector::{
    BitVectorProof as HrBitVectorProof, BitVectorStatement, BitVectorWitness,
};
use aura::proofs::commitment_set::{
    CommitmentSetParams, CommitmentSetProof as HrCommitmentSetProof, CommitmentSetStatement,
    CommitmentSetWitness,
};
use aura::proofs::dleq::{
    DleqProof as HrDleqProof, DleqStatement, DleqWitness,
};
use aura::proofs::encryption_validity::{
    EncValStatement, EncValWitness, EncryptionValidityProof as HrEncryptionValidityProof,
};
use aura::proofs::representation::{
    RepresentationProof as HrRepresentationProof, RepresentationStatement, RepresentationWitness,
};
use aura::proofs::serial_validity::{
    SerValStatement, SerValWitness, SerialValidityProof as HrSerialValidityProof,
};

use aura::proofs::lib_backed::bit_vector::BitVectorProof as LibBitVectorProof;
use aura::proofs::lib_backed::commitment_set::CommitmentSetProof as LibCommitmentSetProof;
use aura::proofs::lib_backed::dleq::DleqProof as LibDleqProof;
use aura::proofs::lib_backed::encryption_validity::EncryptionValidityProof as LibEncryptionValidityProof;
use aura::proofs::lib_backed::representation::RepresentationProof as LibRepresentationProof;
use aura::proofs::lib_backed::serial_validity::SerialValidityProof as LibSerialValidityProof;

fn bench_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(20260412)
}

fn bench_representation(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("rep_compare");
    group.sample_size(50);

    for n in [1usize, 2, 4] {
        let gens: Vec<RistrettoPoint> =
            (0..n).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let scs: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let target = RistrettoPoint::multiscalar_mul(&scs, &gens);
        let st = RepresentationStatement { generators: gens, target };
        let wi_hr = RepresentationWitness { scalars: scs.clone() };
        let wi_lib = RepresentationWitness { scalars: scs.clone() };

        group.bench_with_input(BenchmarkId::new("prove/handrolled", n), &n, |b, _| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                HrRepresentationProof::prove(&st, &wi_hr, &mut t, &mut rng).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("prove/lib", n), &n, |b, _| {
            let mut rng = bench_rng();
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                LibRepresentationProof::prove(&st, &wi_lib, &mut t, &mut rng).unwrap()
            })
        });

        let mut rng_hr = bench_rng();
        let mut t = Transcript::new(b"b");
        let pr_hr = HrRepresentationProof::prove(&st, &wi_hr, &mut t, &mut rng_hr).unwrap();
        let mut rng_lib = bench_rng();
        let mut t = Transcript::new(b"b");
        let pr_lib = LibRepresentationProof::prove(&st, &wi_lib, &mut t, &mut rng_lib).unwrap();

        group.bench_with_input(BenchmarkId::new("verify/handrolled", n), &n, |b, _| {
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                pr_hr.verify(&st, &mut t).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("verify/lib", n), &n, |b, _| {
            b.iter(|| {
                let mut t = Transcript::new(b"b");
                pr_lib.verify(&st, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

fn bench_dleq(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("dleq_compare");
    group.sample_size(50);

    let g = RistrettoPoint::random(&mut rng);
    let h = RistrettoPoint::random(&mut rng);
    let a = Scalar::random(&mut rng);
    let st = DleqStatement {
        g,
        h,
        y: a * g,
        y_prime: a * h,
    };
    let wi = DleqWitness { scalar: a };

    group.bench_function("prove/handrolled", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            HrDleqProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
        })
    });
    group.bench_function("prove/lib", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            LibDleqProof::prove(&st, &wi, &mut t, &mut rng).unwrap()
        })
    });

    let mut rng_hr = bench_rng();
    let mut t = Transcript::new(b"b");
    let pr_hr = HrDleqProof::prove(&st, &wi, &mut t, &mut rng_hr).unwrap();
    let mut rng_lib = bench_rng();
    let mut t = Transcript::new(b"b");
    let pr_lib = LibDleqProof::prove(&st, &wi, &mut t, &mut rng_lib).unwrap();

    group.bench_function("verify/handrolled", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr_hr.verify(&st, &mut t).unwrap()
        })
    });
    group.bench_function("verify/lib", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr_lib.verify(&st, &mut t).unwrap()
        })
    });
    group.finish();
}

fn bench_encryption_validity(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("encval_compare");
    group.sample_size(50);

    let g = RistrettoPoint::random(&mut rng);
    let h_i = RistrettoPoint::random(&mut rng);
    let sk = Scalar::random(&mut rng);
    let y = sk * g;
    let r = Scalar::random(&mut rng);
    let m = Scalar::from(1u64);
    let d = r * g;
    let e = r * y + m * h_i;
    let st = EncValStatement { g, y, h_i, d, e };
    let wi_hr = EncValWitness { r, m };
    let wi_lib = EncValWitness { r, m };

    group.bench_function("prove/handrolled", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            HrEncryptionValidityProof::prove(&st, &wi_hr, &mut t, &mut rng).unwrap()
        })
    });
    group.bench_function("prove/lib", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            LibEncryptionValidityProof::prove(&st, &wi_lib, &mut t, &mut rng).unwrap()
        })
    });

    let mut rng_hr = bench_rng();
    let mut t = Transcript::new(b"b");
    let pr_hr = HrEncryptionValidityProof::prove(&st, &wi_hr, &mut t, &mut rng_hr).unwrap();
    let mut rng_lib = bench_rng();
    let mut t = Transcript::new(b"b");
    let pr_lib = LibEncryptionValidityProof::prove(&st, &wi_lib, &mut t, &mut rng_lib).unwrap();

    group.bench_function("verify/handrolled", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr_hr.verify(&st, &mut t).unwrap()
        })
    });
    group.bench_function("verify/lib", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr_lib.verify(&st, &mut t).unwrap()
        })
    });
    group.finish();
}

fn bench_serial_validity(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("serval_compare");
    group.sample_size(50);

    let f = RistrettoPoint::random(&mut rng);
    let g = RistrettoPoint::random(&mut rng);
    let h = RistrettoPoint::random(&mut rng);
    let sk = Scalar::random(&mut rng);
    let y = sk * g;
    let s = Scalar::random(&mut rng);
    let r_prime = Scalar::random(&mut rng);
    let r_double_prime = Scalar::random(&mut rng);
    let c_prime = s * g + r_prime * h;
    let d_prime = r_double_prime * g;
    let e_prime = s * f + r_double_prime * y;
    let st = SerValStatement { f, g, h, y, c_prime, d_prime, e_prime };
    let wi_hr = SerValWitness { s, r_prime, r_double_prime };
    let wi_lib = SerValWitness { s, r_prime, r_double_prime };

    group.bench_function("prove/handrolled", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            HrSerialValidityProof::prove(&st, &wi_hr, &mut t, &mut rng).unwrap()
        })
    });
    group.bench_function("prove/lib", |b| {
        let mut rng = bench_rng();
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            LibSerialValidityProof::prove(&st, &wi_lib, &mut t, &mut rng).unwrap()
        })
    });

    let mut rng_hr = bench_rng();
    let mut t = Transcript::new(b"b");
    let pr_hr = HrSerialValidityProof::prove(&st, &wi_hr, &mut t, &mut rng_hr).unwrap();
    let mut rng_lib = bench_rng();
    let mut t = Transcript::new(b"b");
    let pr_lib = LibSerialValidityProof::prove(&st, &wi_lib, &mut t, &mut rng_lib).unwrap();

    group.bench_function("verify/handrolled", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr_hr.verify(&st, &mut t).unwrap()
        })
    });
    group.bench_function("verify/lib", |b| {
        b.iter(|| {
            let mut t = Transcript::new(b"b");
            pr_lib.verify(&st, &mut t).unwrap()
        })
    });
    group.finish();
}

fn bench_bit_vector(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("bitvec_compare");
    group.sample_size(20);

    for k in [16usize, 64] {
        let w = (k as u32) / 4; // arbitrary weight
        let gens: Vec<RistrettoPoint> =
            (0..k).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let h = RistrettoPoint::random(&mut rng);
        let mut bits = vec![Scalar::ZERO; k];
        for i in 0..w as usize {
            bits[i] = Scalar::ONE;
        }
        let blinding = Scalar::random(&mut rng);
        let mut scs = vec![blinding];
        let mut pts = vec![h];
        for (bi, gi) in bits.iter().zip(gens.iter()) {
            scs.push(*bi);
            pts.push(*gi);
        }
        let b = RistrettoPoint::multiscalar_mul(&scs, &pts);
        let st = BitVectorStatement {
            generators: gens,
            h,
            b,
            w,
        };
        let wi_hr = BitVectorWitness {
            bits: bits.clone(),
            blinding,
        };
        let wi_lib = BitVectorWitness {
            bits: bits.clone(),
            blinding,
        };

        group.bench_with_input(BenchmarkId::new("prove/handrolled", k), &k, |bn, _| {
            let mut rng = bench_rng();
            bn.iter(|| {
                let mut t = Transcript::new(b"b");
                HrBitVectorProof::prove(&st, &wi_hr, &mut t, &mut rng).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("prove/lib", k), &k, |bn, _| {
            let mut rng = bench_rng();
            bn.iter(|| {
                let mut t = Transcript::new(b"b");
                LibBitVectorProof::prove(&st, &wi_lib, &mut t, &mut rng).unwrap()
            })
        });

        let mut rng_hr = bench_rng();
        let mut t = Transcript::new(b"b");
        let pr_hr = HrBitVectorProof::prove(&st, &wi_hr, &mut t, &mut rng_hr).unwrap();
        let mut rng_lib = bench_rng();
        let mut t = Transcript::new(b"b");
        let pr_lib = LibBitVectorProof::prove(&st, &wi_lib, &mut t, &mut rng_lib).unwrap();

        group.bench_with_input(BenchmarkId::new("verify/handrolled", k), &k, |bn, _| {
            bn.iter(|| {
                let mut t = Transcript::new(b"b");
                pr_hr.verify(&st, &mut t).unwrap()
            })
        });
        group.bench_with_input(BenchmarkId::new("verify/lib", k), &k, |bn, _| {
            bn.iter(|| {
                let mut t = Transcript::new(b"b");
                pr_lib.verify(&st, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

fn bench_commitment_set(c: &mut Criterion) {
    let mut rng = bench_rng();
    let mut group = c.benchmark_group("set_compare");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(10));

    // Power-of-two N for the lib-backed proof. n=2,m=8 → N=256; n=2,m=10 → 1024.
    for (n_param, m_param) in [(2u32, 8u32), (2, 10)] {
        let big_n = (n_param as usize).pow(m_param);
        let secret_index = (big_n / 3) as u32;

        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);
        let commitments: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| Scalar::random(&mut rng) * g + Scalar::random(&mut rng) * h)
            .collect();
        let blinding = Scalar::random(&mut rng);
        let c_prime = commitments[secret_index as usize] - blinding * h;
        let params = CommitmentSetParams {
            n: n_param,
            m: m_param,
            g,
            h,
        };
        let st = CommitmentSetStatement {
            params,
            commitments,
            c_prime,
        };
        let wi_hr = CommitmentSetWitness {
            index: secret_index,
            blinding,
        };
        let wi_lib = CommitmentSetWitness {
            index: secret_index,
            blinding,
        };

        let label = format!("N={big_n}");
        group.bench_with_input(
            BenchmarkId::new("prove/handrolled", &label),
            &big_n,
            |bn, _| {
                let mut rng = bench_rng();
                bn.iter(|| {
                    let mut t = Transcript::new(b"b");
                    HrCommitmentSetProof::prove(&st, &wi_hr, &mut t, &mut rng).unwrap()
                })
            },
        );
        group.bench_with_input(BenchmarkId::new("prove/lib", &label), &big_n, |bn, _| {
            let mut rng = bench_rng();
            bn.iter(|| {
                let mut t = Transcript::new(b"b");
                LibCommitmentSetProof::prove(&st, &wi_lib, &mut t, &mut rng).unwrap()
            })
        });

        let mut rng_hr = bench_rng();
        let mut t = Transcript::new(b"b");
        let pr_hr = HrCommitmentSetProof::prove(&st, &wi_hr, &mut t, &mut rng_hr).unwrap();
        let mut rng_lib = bench_rng();
        let mut t = Transcript::new(b"b");
        let pr_lib = LibCommitmentSetProof::prove(&st, &wi_lib, &mut t, &mut rng_lib).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify/handrolled", &label),
            &big_n,
            |bn, _| {
                bn.iter(|| {
                    let mut t = Transcript::new(b"b");
                    pr_hr.verify(&st, &mut t).unwrap()
                })
            },
        );
        group.bench_with_input(BenchmarkId::new("verify/lib", &label), &big_n, |bn, _| {
            bn.iter(|| {
                let mut t = Transcript::new(b"b");
                pr_lib.verify(&st, &mut t).unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = bench_representation, bench_dleq, bench_encryption_validity, bench_serial_validity, bench_bit_vector, bench_commitment_set
);
criterion_main!(benches);
