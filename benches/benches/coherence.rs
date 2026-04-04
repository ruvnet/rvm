//! Benchmark the coherence EMA filter.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rvm_coherence::EmaFilter;

fn bench_ema_update(c: &mut Criterion) {
    c.bench_function("ema_filter_update", |b| {
        let mut filter = EmaFilter::new(2000);
        let mut sample = 0u16;
        b.iter(|| {
            sample = sample.wrapping_add(100);
            black_box(filter.update(sample));
        });
    });
}

criterion_group!(benches, bench_ema_update);
criterion_main!(benches);
