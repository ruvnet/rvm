//! Benchmarks for the `ruv://` naming and scope-containment path.
//!
//! These two groups cover what a host authorization gate actually runs per
//! request: parse the name, then decide whether it falls inside a granted
//! scope. Scope containment is the whole shadow-mode question — it needs no
//! capability, no runtime and no key — so it is worth measuring on its own.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rvm_context::{ContextScope, ContextViewMask, RuvUri};

const ALIAS: &str =
    "ruv://context.example/acme/agent/researcher/resources/projects/orion/spec?view=overview";
const PINNED: &str = concat!(
    "ruv://context.example/acme/agent/researcher/skills/web-search?rev=sha256:",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "&view=content",
);
const BARE: &str = "ruv://context.example/acme/agent/researcher/memory";

fn bench_context_uri(c: &mut Criterion) {
    c.bench_function("ruv_uri_parse_alias", |b| {
        b.iter(|| RuvUri::parse(black_box(ALIAS)).unwrap());
    });
    c.bench_function("ruv_uri_parse_pinned", |b| {
        b.iter(|| RuvUri::parse(black_box(PINNED)).unwrap());
    });
    c.bench_function("ruv_uri_parse_bare", |b| {
        b.iter(|| RuvUri::parse(black_box(BARE)).unwrap());
    });

    let parsed = RuvUri::parse(PINNED).unwrap();
    c.bench_function("ruv_uri_format_pinned", |b| {
        b.iter(|| black_box(&parsed).to_string());
    });
}

fn bench_scope(c: &mut Criterion) {
    let mask = ContextViewMask::from_bits(0b0000_0111).expect("mask");
    let root = RuvUri::parse("ruv://context.example/acme/agent/researcher/resources").unwrap();
    let granted = ContextScope::from_uri(&root, mask);

    // Inside the grant, three segments deeper.
    let inside = ContextScope::from_uri(&RuvUri::parse(ALIAS).unwrap(), mask);
    // A different tenant: the cross-tenant reach a gateway must refuse.
    let other_tenant = ContextScope::from_uri(
        &RuvUri::parse("ruv://context.example/borl/agent/researcher/resources/projects").unwrap(),
        mask,
    );
    // Same tenant and prefix depth, diverging at the LAST prefix segment —
    // the position a short-circuiting comparison gets wrong.
    let diverges_last = ContextScope::from_uri(
        &RuvUri::parse("ruv://context.example/acme/agent/researcher/skills/projects/orion/spec")
            .unwrap(),
        mask,
    );

    c.bench_function("scope_from_uri", |b| {
        b.iter(|| ContextScope::from_uri(black_box(&root), black_box(mask)));
    });
    c.bench_function("scope_contains_hit", |b| {
        b.iter(|| black_box(&granted).contains_scope(black_box(&inside)));
    });
    c.bench_function("scope_contains_miss_tenant", |b| {
        b.iter(|| black_box(&granted).contains_scope(black_box(&other_tenant)));
    });
    c.bench_function("scope_contains_miss_last_segment", |b| {
        b.iter(|| black_box(&granted).contains_scope(black_box(&diverges_last)));
    });
}

criterion_group!(benches, bench_context_uri, bench_scope);
criterion_main!(benches);
