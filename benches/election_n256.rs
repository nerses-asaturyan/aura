#[path = "bench_common.rs"]
mod bench_common;

use criterion::{criterion_group, criterion_main, Criterion};

fn bench(c: &mut Criterion) {
    bench_common::bench_election_suite(c, 2, 8); // N = 2^8 = 256
}

criterion_group!(benches, bench);
criterion_main!(benches);
