//! Randomized panic hunt over rvm-rvf walk/verify and the streaming session.
mod stream_common;
use rvm_rvf::stream::builder::Order;
use std::panic::{catch_unwind, AssertUnwindSafe};
use stream_common::*;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

fn rng(seed: u64) -> impl FnMut() -> u64 { let mut x = seed | 1; move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x } }
fn msg(e: Box<dyn std::any::Any + Send>) -> String { e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default() }

#[test]
fn walk_verify_and_session_never_panic_on_mutated_input() {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&body).unwrap();
    let mut r = rng(0xFACE);
    let mut panics = Vec::new();
    for i in 0..20_000 {
        // Container: mutate / truncate the plain body for walk + verify.
        let mut c = body.clone();
        for _ in 0..(1 + r() % 24) { let at = (r() as usize) % c.len(); c[at] = r() as u8; }
        if i % 5 == 0 { c.truncate((r() as usize) % (c.len() + 1)); }
        if let Err(e) = catch_unwind(AssertUnwindSafe(|| { let _ = rvm_rvf::walk(&c); let _ = rvm_rvf::verify(&c, &opts()); })) {
            panics.push((i, "walk/verify", msg(e)));
        }
        // Stream: mutate frames, drop/duplicate/reorder some, push through a session.
        let mut frames = bundle.frames.clone();
        for _ in 0..(1 + r() % 4) {
            match r() % 4 {
                0 => { let f = (r() as usize) % frames.len(); let l = frames[f].len(); if l > 0 { let at = (r() as usize) % l; frames[f][at] = r() as u8; } }
                1 => { let f = (r() as usize) % frames.len(); frames.remove(f); if frames.is_empty() { break; } }
                2 => { let f = (r() as usize) % frames.len(); let d = frames[f].clone(); frames.insert((r() as usize) % frames.len(), d); }
                _ => { let a = (r() as usize) % frames.len(); let z = (r() as usize) % frames.len(); frames.swap(a, z); }
            }
        }
        if let Err(e) = catch_unwind(AssertUnwindSafe(|| {
            let mut s = stream(&keys, bundle.clone(), base_policy());
            for f in &frames { let _ = s.session.push(f); }
            let _ = s.session.report(); let _ = s.session.take_module(2);
        })) { panics.push((i, "session", msg(e))); }
        if panics.len() >= 5 { break; }
    }
    assert!(panics.is_empty(), "panics: {panics:?}");
}
