//! N = 2^20 = 1,048,576 voters.
//! Benchmarks ballot-level operations only (full tally fixture too expensive).

#[path = "bench_large.rs"]
mod bench_large;

use criterion::{criterion_group, criterion_main, Criterion};

fn bench(c: &mut Criterion) {
    bench_large::bench_ballot_only(c, 2, 20); // N = 2^20 = 1048576
}

criterion_group!(benches, bench);
criterion_main!(benches);
