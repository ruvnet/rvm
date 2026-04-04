//! Benchmark witness log operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rvm_types::WitnessRecord;
use rvm_witness::WitnessLog;

fn bench_witness_append(c: &mut Criterion) {
    c.bench_function("witness_log_append_256", |b| {
        let mut log = WitnessLog::<256>::new();
        b.iter(|| {
            black_box(log.append(WitnessRecord::zeroed()));
        });
    });
}

criterion_group!(benches, bench_witness_append);
criterion_main!(benches);
