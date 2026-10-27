//! RV3-01 (fixed): the identity worker thread (`parallel-identity`) is joined as
//! soon as the stream is poisoned, completes, suspends or the running hash
//! becomes infeasible, and is never started for a stage-ordered plan. Without
//! the feature there is no worker and the assertions hold trivially.
//!
//! Counts threads named `rvm-rvf-identity`, in a test binary of its own and
//! serialised, so other tests cannot disturb the count.

mod common;

use common::{builder, good_body, noise};
use rvm_rvf::stream::builder::{Order, Stages};
use rvm_rvf::stream::{IdentityStatus, StreamError, StreamPolicy, StreamState, StreamVerifier};
use rvm_rvf::testkit::unsigned_segment;
use std::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::new(());

fn big_body(mib: usize) -> Vec<u8> {
    let mut b = good_body();
    b.extend(unsigned_segment(0x01, &noise(mib << 20, 3), 50));
    b
}

/// Live identity worker threads (the kernel truncates names to 15 bytes).
fn workers() -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(|e| std::fs::read_to_string(e.unwrap().path().join("comm")).ok())
        .filter(|c| c.trim() == "rvm-rvf-identit")
        .count()
}

fn pol(keys: &[[u8; 32]]) -> StreamPolicy<'_> {
    StreamPolicy::unpinned_insecure(keys)
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "counts threads via /proc/self/task (Linux only)")]
fn rv3_01_worker_thread_is_joined_at_poison_completion_suspend_and_infeasibility() {
    let body = big_body(5);
    let b = builder(16, Order::File);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(workers(), 0);

    // Poisoned: the worker is gone while the verifier is still alive.
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut v = StreamVerifier::new(pol(&keys));
        v.push(&bundle.frames[0]).unwrap();
        v.push(&bundle.frames[1]).unwrap();
        v.poison(StreamError::FrameSizeLie);
        assert!(matches!(v.state(), StreamState::Poisoned(_)));
        held.push(v);
    }
    assert_eq!(workers(), 0, "poisoned");

    // Completed: same.
    let mut done = Vec::new();
    for _ in 0..8 {
        let mut v = StreamVerifier::new(pol(&keys));
        for f in &bundle.frames {
            v.push(f).unwrap();
        }
        assert_eq!(v.state(), StreamState::Complete);
        done.push(v);
    }
    assert_eq!(workers(), 0, "complete");

    // Suspended: released, and the stream still completes correctly after resume.
    let mut v = StreamVerifier::new(pol(&keys));
    let half = bundle.frames.len() / 2;
    for f in &bundle.frames[..half] {
        v.push(f).unwrap();
    }
    v.end_of_input();
    assert_eq!(workers(), 0, "suspended");
    assert!(v.resume());
    for f in &bundle.frames[half..] {
        v.push(f).unwrap();
    }
    assert_eq!(v.state(), StreamState::Complete);
    assert_eq!(v.identity_status(), Some(IdentityStatus::Verified));

    // Out of file order: the second segment's chunk arrives before the first.
    // The worker is released at that chunk and the identity can no longer be
    // confirmed by the running hash (reported unverifiable, never wrong).
    let mut v = StreamVerifier::new(pol(&keys));
    v.push(&bundle.frames[0]).unwrap();
    assert_eq!(
        workers(),
        1.min(usize::from(cfg!(feature = "parallel-identity")))
    );
    v.push(&bundle.frames[2]).unwrap();
    assert_eq!(workers(), 0, "out of order");
    drop((held, done));
}

/// Stage-ordered delivery is expected out of file order: no worker at all.
#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "counts threads via /proc/self/task (Linux only)")]
fn rv3_01_stage_order_does_not_spawn_a_worker() {
    let body = big_body(5);
    let mut b = builder(16, Order::Stage);
    b.stages = Stages::ByType;
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut v = StreamVerifier::new(pol(&keys));
        v.push(&bundle.frames[0]).unwrap();
        v.push(&bundle.frames[1]).unwrap();
        held.push(v);
    }
    assert_eq!(workers(), 0, "no worker for a stage plan");
}

/// Control: with the feature, the worker really is running mid-stream (so the
/// zero counts above mean something).
#[cfg(feature = "parallel-identity")]
#[test]
fn rv3_01_control_the_worker_runs_while_the_stream_is_in_flight() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let body = big_body(5);
    let b = builder(16, Order::File);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mut v = StreamVerifier::new(pol(&keys));
    v.push(&bundle.frames[0]).unwrap();
    v.push(&bundle.frames[1]).unwrap();
    assert_eq!(workers(), 1);
    drop(v);
    assert_eq!(workers(), 0, "joined on drop");
}
