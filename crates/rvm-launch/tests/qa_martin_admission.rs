//! Independent QA (Martin, 2026-10-27): a refused stream must not leave an admissible report.
mod stream_common;
use rvm_launch::SessionError;
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::FRAME_DESCRIPTOR;
use stream_common::*;

#[test]
fn module_rejected_at_finish_must_not_leave_an_ok_report() {
    // Valid framing (passes validate_module), but 1 function and no code section: only the
    // whole-module check in finish() rejects it.
    let bad = vec![0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0];
    assert!(rvm_wasm::validate_module(&bad).is_ok(), "framing-only check accepts it");
    let body = package_body(&bad, "clock", 2);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    // Deliver the WASM segment (seg 2) last so its completion is the stream's completion.
    let (mut wasm, mut rest): (Vec<_>, Vec<_>) = s.bundle.frames.clone().into_iter()
        .partition(|f| f[0] != FRAME_DESCRIPTOR && f.len() >= 9 && u64::from_le_bytes(f[1..9].try_into().unwrap()) == 2);
    assert!(!wasm.is_empty(), "found the WASM segment's frames");
    rest.append(&mut wasm);
    for f in &rest { let _ = s.session.push(f); }
    let failure = s.session.failure().cloned();
    eprintln!("failure: {failure:?}");
    assert!(matches!(failure, Some(SessionError::Module { .. })), "the module is refused");
    if let Some(r) = s.session.report() {
        eprintln!("report kept after refusal: ok={}", r.ok);
        let pkg = rvm_host::VerifiedPackage::from_report(r);
        eprintln!("VerifiedPackage::from_report on the refused stream: {}", if pkg.is_ok() { "Ok (package built)" } else { "Err" });
        if let Ok(p) = &pkg { eprintln!("accepts_wasm(refused module) = {}", p.accepts_wasm(&bad)); }
        assert!(!r.ok, "BUG: report().ok is true after the module was refused");
        assert!(rvm_host::VerifiedPackage::from_report(r).is_err(), "BUG: a VerifiedPackage can be built from a refused stream");
    }
}
