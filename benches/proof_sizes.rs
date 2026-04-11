//! Benchmark suite: proof sizes (in bytes) for all proof types and ballot sizes.
//!
//! This is not a timing benchmark — it uses Criterion's custom measurement
//! infrastructure to report sizes. Run with:
//!   cargo bench --bench proof_sizes
//!
//! Alternatively, run as a standalone size report:
//!   cargo bench --bench proof_sizes -- --quick

use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use merlin::Transcript;
use rand::rngs::OsRng;

use aura::proofs::bit_vector::{BitVectorProof, BitVectorStatement, BitVectorWitness};
use aura::proofs::commitment_set::{
    CommitmentSetParams, CommitmentSetProof, CommitmentSetStatement, CommitmentSetWitness,
};
use aura::proofs::representation::{
    RepresentationProof, RepresentationStatement, RepresentationWitness,
};

const POINT_SIZE: usize = 32; // CompressedRistretto
const SCALAR_SIZE: usize = 32;

// ── Size computation functions ──────────────────────────────────────────

fn rep_proof_size(num_generators: usize) -> usize {
    // commitment: 1 point, responses: n scalars
    POINT_SIZE + num_generators * SCALAR_SIZE
}

fn dleq_proof_size() -> usize {
    // 2 points + 1 scalar
    2 * POINT_SIZE + SCALAR_SIZE
}

fn encval_proof_size() -> usize {
    // 2 points + 2 scalars
    2 * POINT_SIZE + 2 * SCALAR_SIZE
}

fn serval_proof_size() -> usize {
    // 3 points + 3 scalars
    3 * POINT_SIZE + 3 * SCALAR_SIZE
}

fn bitvec_proof_size(k_prime: usize) -> usize {
    // 3 points + (k'-1) scalars + 2 scalars
    3 * POINT_SIZE + (k_prime - 1) * SCALAR_SIZE + 2 * SCALAR_SIZE
}

fn set_proof_size(n: usize, m: usize) -> usize {
    // cl: m*n points, cross_terms: m points, f_matrix: m*n scalars, z: 1 scalar
    m * n * POINT_SIZE + m * POINT_SIZE + m * n * SCALAR_SIZE + SCALAR_SIZE
}

fn ciphertext_size() -> usize {
    2 * POINT_SIZE
}

fn signature_size() -> usize {
    POINT_SIZE + SCALAR_SIZE
}

fn ballot_size(k_prime: usize, n: usize, m: usize) -> usize {
    // encrypted_choices: k' * (ciphertext + encval_proof)
    let enc_choices = k_prime * (ciphertext_size() + encval_proof_size());
    // bit_proof
    let bit = bitvec_proof_size(k_prime);
    // serial_offset: 1 point
    let serial_offset = POINT_SIZE;
    // encrypted_serial: 1 ciphertext
    let enc_serial = ciphertext_size();
    // set_proof
    let set = set_proof_size(n, m);
    // serial_proof
    let ser = serval_proof_size();
    // signature
    let sig = signature_size();

    enc_choices + bit + serial_offset + enc_serial + set + ser + sig
}

// ── Print all sizes ─────────────────────────────────────────────────────

fn bench_print_sizes(c: &mut Criterion) {
    // Print a comprehensive size report
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                  AURA PROOF SIZE REPORT                         ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║ Element sizes: Point = {} B, Scalar = {} B                      ║", POINT_SIZE, SCALAR_SIZE);
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                ║");
    println!("║ INDIVIDUAL PROOF SIZES                                         ║");
    println!("║                                                                ║");
    println!("║  Representation (n=2):    {:>6} B  ({:>3} elements)              ║",
        rep_proof_size(2), 1 + 2);
    println!("║  DLEQ:                    {:>6} B  ({:>3} elements)              ║",
        dleq_proof_size(), 3);
    println!("║  Encryption validity:     {:>6} B  ({:>3} elements)              ║",
        encval_proof_size(), 4);
    println!("║  Serial validity:         {:>6} B  ({:>3} elements)              ║",
        serval_proof_size(), 6);
    println!("║                                                                ║");

    // Bit vector for various k'
    println!("║ BIT VECTOR PROOF SIZES (varies with k')                        ║");
    println!("║                                                                ║");
    for k in [4, 5, 8, 16, 32, 64] {
        println!("║  k'={:<3}:                  {:>6} B  ({:>3} elements)              ║",
            k, bitvec_proof_size(k), 3 + (k - 1) + 2);
    }

    // Commitment set for various N
    println!("║                                                                ║");
    println!("║ COMMITMENT SET PROOF SIZES (varies with N = n^m)               ║");
    println!("║                                                                ║");
    for (n, m, n_voters) in [
        (2, 4, 16), (2, 6, 64), (2, 8, 256), (2, 10, 1024),
        (2, 12, 4096), (2, 14, 16384), (2, 16, 65536),
        (2, 18, 262144), (2, 20, 1048576),
    ] {
        println!("║  N={:<10} (n={},m={:<2}): {:>6} B  ({:>3} elements)              ║",
            n_voters, n, m, set_proof_size(n, m), 2 * n * m + m + 1);
    }

    // Full ballot sizes (4 choices, kmin=1, kmax=2, so k'=5)
    println!("║                                                                ║");
    println!("║ FULL BALLOT SIZES (k=4, kmin=1, kmax=2, k'=5)                 ║");
    println!("║                                                                ║");
    for (n, m, n_voters) in [
        (2, 4, 16), (2, 6, 64), (2, 8, 256), (2, 10, 1024),
        (2, 12, 4096), (2, 14, 16384), (2, 16, 65536),
        (2, 18, 262144), (2, 20, 1048576),
    ] {
        let k_prime = 5; // 4 + 2 - 1
        let total = ballot_size(k_prime, n, m);
        println!("║  N={:<10}:            {:>6} B  ({:.1} KB)                   ║",
            n_voters, total, total as f64 / 1024.0);
    }

    println!("║                                                                ║");
    println!("║ COMPARISON WITH ELECTIONGUARD (k'=5)                           ║");
    println!("║                                                                ║");
    let k_prime = 5;
    let aura_batch = 5 * k_prime + 4;
    let aura_no_batch = 4 * k_prime + 4;
    let eg_batch = 8 * k_prime + 3;
    let eg_no_batch = 4 * k_prime + 2;
    println!("║  Aura (batch):       {:>3} elements  ({:>5} B)                  ║",
        aura_batch, aura_batch * 32);
    println!("║  Aura (no batch):    {:>3} elements  ({:>5} B)                  ║",
        aura_no_batch, aura_no_batch * 32);
    println!("║  ElectionGuard (batch):  {:>3} elements  ({:>5} B)              ║",
        eg_batch, eg_batch * 32);
    println!("║  ElectionGuard (no batch): {:>3} elements  ({:>5} B)            ║",
        eg_no_batch, eg_no_batch * 32);

    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    // Criterion needs at least one benchmark to not crash
    c.bench_function("_size_report_noop", |b| b.iter(|| 1 + 1));
}

// ── Verify computed sizes match actual serialized sizes ─────────────────

fn bench_verify_actual_sizes(c: &mut Criterion) {
    let mut rng = OsRng;
    let mut group = c.benchmark_group("actual_proof_sizes");
    group.sample_size(10);

    // Generate actual proofs and count their elements
    println!();
    println!("── Actual vs computed size verification ──");

    // Representation (n=2)
    {
        let gens: Vec<RistrettoPoint> = (0..2).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let scs: Vec<Scalar> = (0..2).map(|_| Scalar::random(&mut rng)).collect();
        let target = RistrettoPoint::multiscalar_mul(&scs, &gens);
        let st = RepresentationStatement { generators: gens, target };
        let wi = RepresentationWitness { scalars: scs };
        let mut t = Transcript::new(b"b");
        let pr = RepresentationProof::prove(&st, &wi, &mut t, &mut rng).unwrap();
        let actual = POINT_SIZE + pr.responses.len() * SCALAR_SIZE;
        let computed = rep_proof_size(2);
        println!("  RepProof(n=2): actual={} B, computed={} B  {}", actual, computed,
            if actual == computed { "OK" } else { "MISMATCH!" });
    }

    // CommitmentSet (n=2, m=8, N=256)
    {
        let n = 2usize;
        let m = 8usize;
        let big_n = 256;
        let g = RistrettoPoint::random(&mut rng);
        let h = RistrettoPoint::random(&mut rng);
        let comms: Vec<RistrettoPoint> = (0..big_n)
            .map(|_| Scalar::random(&mut rng) * g + Scalar::random(&mut rng) * h)
            .collect();
        let bl = Scalar::random(&mut rng);
        let cp = comms[100] - bl * h;
        let params = CommitmentSetParams { n: n as u32, m: m as u32, g, h };
        let st = CommitmentSetStatement { params, commitments: comms, c_prime: cp };
        let wi = CommitmentSetWitness { index: 100, blinding: bl };
        let mut t = Transcript::new(b"b");
        let pr = CommitmentSetProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

        let actual_cl: usize = pr.cl.iter().map(|v| v.len() * POINT_SIZE).sum();
        let actual_cross = pr.cross_terms.len() * POINT_SIZE;
        let actual_f: usize = pr.f_matrix.iter().map(|v| v.len() * SCALAR_SIZE).sum();
        let actual = actual_cl + actual_cross + actual_f + SCALAR_SIZE;
        let computed = set_proof_size(n, m);
        println!("  SetProof(N=256): actual={} B, computed={} B  {}", actual, computed,
            if actual == computed { "OK" } else { "MISMATCH!" });
    }

    // BitVector (k'=5)
    {
        let k = 5;
        let gens: Vec<RistrettoPoint> = (0..k).map(|_| RistrettoPoint::random(&mut rng)).collect();
        let h = RistrettoPoint::random(&mut rng);
        let mut bits = vec![Scalar::ZERO; k];
        bits[0] = Scalar::ONE;
        bits[1] = Scalar::ONE;
        let bl = Scalar::random(&mut rng);
        let mut sc = vec![bl];
        let mut pt = vec![h];
        for (bi, gi) in bits.iter().zip(gens.iter()) {
            sc.push(*bi);
            pt.push(*gi);
        }
        let bp = RistrettoPoint::multiscalar_mul(&sc, &pt);
        let st = BitVectorStatement { generators: gens, h, b: bp, w: 2 };
        let wi = BitVectorWitness { bits, blinding: bl };
        let mut t = Transcript::new(b"b");
        let pr = BitVectorProof::prove(&st, &wi, &mut t, &mut rng).unwrap();

        let actual = 3 * POINT_SIZE + pr.f.len() * SCALAR_SIZE + 2 * SCALAR_SIZE;
        let computed = bitvec_proof_size(k);
        println!("  BitVecProof(k'=5): actual={} B, computed={} B  {}", actual, computed,
            if actual == computed { "OK" } else { "MISMATCH!" });
    }

    println!();

    group.bench_function("noop", |b| b.iter(|| 1 + 1));
    group.finish();
}

criterion_group!(
    benches,
    bench_print_sizes,
    bench_verify_actual_sizes,
);
criterion_main!(benches);
