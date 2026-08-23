//! Cross-implementation determinism.
//!
//! Every assertion here runs twice: natively via `cargo test`, and on
//! `wasm32-unknown-unknown` under Node via `wasm-pack test --node`. The
//! expected values are hardcoded, so if the two targets ever disagree about
//! canonical bytes, one of the two runs fails rather than drifting silently.
//!
//! This is the property that keeps policy scopes, witness records, signatures,
//! and caches from disagreeing about identity across targets.
//!
//! Only success paths appear here: constructing a `JsValue` error outside wasm
//! panics, so rejection behaviour lives in `binding.rs`, which is wasm-only.

use rvm_context_wasm::{ContextScope, Rights, RuvUri, RuvUriBuilder, ViewMask};
use rvm_types::WitnessRecord;

const AUTHORITY: &str = "context.example";
const TENANT: &str = "acme";
const ZERO_REV: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Canonical URI formatting must be byte-identical on both targets.
fn canonical_uri_bytes_are_stable() {
    let cases: [&str; 5] = [
        "ruv://context.example/acme/agent/researcher/memory",
        "ruv://context.example/acme/team/core/resources/Specs/API_v1",
        "ruv://a.b.c/t/service/api/skills/deploy?view=content",
        "ruv://context.example/acme/user/alice/memory?rev=sha256:0000000000000000000000000000000000000000000000000000000000000000&view=abstract",
        "ruv://context.example/acme/agent/r/resources/A/b-c/d.e/f_g/h~i",
    ];
    for input in cases {
        let uri = RuvUri::parse(input).expect("case parses");
        assert_eq!(uri.render(), input, "canonical spelling drifted");
        assert_eq!(
            hex(uri.render().as_bytes()),
            hex(input.as_bytes()),
            "canonical bytes drifted"
        );
        // Reparsing the rendered form is a fixed point.
        let again = RuvUri::parse(&uri.render()).expect("reparses");
        assert!(again.equals(&uri));
    }
}

/// The builder must produce exactly the bytes the parser accepts.
fn builder_and_parser_agree() {
    let built = RuvUriBuilder::new(AUTHORITY, TENANT, "agent", "researcher", "memory")
        .expect("components validate")
        .segment("projects")
        .expect("segment validates")
        .segment("atlas")
        .expect("segment validates")
        .revision(ZERO_REV)
        .expect("revision validates")
        .build()
        .expect("limits hold");
    let expected =
        format!("ruv://context.example/acme/agent/researcher/memory/projects/atlas?rev={ZERO_REV}");
    assert_eq!(built.render(), expected);
    assert!(
        RuvUri::parse(&expected).expect("parses").equals(&built),
        "builder and parser disagree"
    );
}

/// Rights bits are a stable wire value and must not drift.
fn rights_bits_are_stable() {
    let expectations: [(&str, u8); 7] = [
        ("resolve", 0x01),
        ("read", 0x01),
        ("put", 0x02),
        ("grant", 0x04),
        ("revoke", 0x08),
        ("execute", 0x10),
        ("sealReceipt", 0x20),
    ];
    for (operation, bits) in expectations {
        let rights = Rights::for_operation(operation).expect("registered operation");
        assert_eq!(rights.bits(), bits, "rights bits drifted for {operation}");
    }
    // Verify requires READ and PROVE together.
    assert_eq!(
        Rights::for_operation("verify").expect("registered").bits(),
        0x21
    );
}

/// View mask bits are a stable wire value.
fn view_mask_bits_are_stable() {
    assert_eq!(ViewMask::all().bits(), 0x0f);
    assert_eq!(ViewMask::manifest().bits(), 0x01);
    assert_eq!(ViewMask::view("abstract").expect("view").bits(), 0x02);
    assert_eq!(ViewMask::view("overview").expect("view").bits(), 0x04);
    assert_eq!(ViewMask::view("content").expect("view").bits(), 0x08);
}

/// Scope containment is a pure predicate and must agree on both targets.
///
/// The violating segment sits at the LAST position of the path. A containment
/// check written as a short-circuiting loop is green for position 1 while
/// broken for positions 2..n, so probing only the first position proves
/// nothing.
fn scope_containment_agrees() {
    let base = "ruv://context.example/acme/agent/researcher/memory";
    let parent = ContextScope::from_uri(
        &RuvUri::parse(&format!("{base}/a/b/c")).expect("parses"),
        &ViewMask::all(),
    );

    // Diverges only at the final prefix segment.
    let last_position = ContextScope::from_uri(
        &RuvUri::parse(&format!("{base}/a/b/X")).expect("parses"),
        &ViewMask::all(),
    );
    assert!(
        !parent.contains_scope(&last_position),
        "divergence at the last prefix segment was not caught"
    );

    // Diverges at the first segment, the easy case.
    let first_position = ContextScope::from_uri(
        &RuvUri::parse(&format!("{base}/X/b/c")).expect("parses"),
        &ViewMask::all(),
    );
    assert!(!parent.contains_scope(&first_position));

    // A genuine descendant is contained, at depth beyond the prefix.
    let descendant = ContextScope::from_uri(
        &RuvUri::parse(&format!("{base}/a/b/c/d/e")).expect("parses"),
        &ViewMask::all(),
    );
    assert!(parent.contains_scope(&descendant));

    // A strict ancestor is not contained by its child.
    let ancestor = ContextScope::from_uri(
        &RuvUri::parse(&format!("{base}/a/b")).expect("parses"),
        &ViewMask::all(),
    );
    assert!(!parent.contains_scope(&ancestor));
    assert!(ancestor.contains_scope(&parent));
}

/// `record_to_digest` is keyless and pure, so its output must be identical on
/// both targets for the same record. This is the anchor that stops witness
/// identity from diverging between the Rust service and the wasm module.
fn witness_record_digests_are_stable() {
    let digests: Vec<String> = scripted_records()
        .iter()
        .map(|record| hex(&rvm_witness::record_to_digest(record)))
        .collect();

    assert_eq!(
        digests, EXPECTED_RECORD_DIGESTS,
        "witness record digests drifted between targets or from the recorded vector"
    );

    // The raw 64-byte record encoding must also be stable, since the digest is
    // taken over it.
    let encodings: Vec<String> = scripted_records()
        .iter()
        .map(|record| hex(&rvm_witness::record_to_bytes(record)))
        .collect();
    assert_eq!(
        encodings, EXPECTED_RECORD_BYTES,
        "witness record encoding drifted"
    );
}

/// A fixed set of witness records with every field pinned, so nothing depends
/// on a clock, on entropy, or on allocation order.
fn scripted_records() -> Vec<WitnessRecord> {
    let mut records = Vec::new();
    for (index, action_kind) in [1_u8, 2, 7].into_iter().enumerate() {
        let mut record = WitnessRecord::zeroed();
        record.sequence = index as u64;
        record.timestamp_ns = (index as u64) * 1_000;
        record.action_kind = action_kind;
        record.proof_tier = 1;
        record.flags = 0;
        record.actor_partition_id = 7;
        record.target_object_id = 0x0102_0304_0506_0708;
        record.capability_hash = 0xdead_beef;
        record.payload = [1, 2, 3, 4, 5, 6, 7, 8];
        record.prev_hash = index as u32;
        record.record_hash = 0xfeed_face;
        record.aux = [9, 10, 11, 12, 13, 14, 15, 16];
        records.push(record);
    }
    records
}

/// Receipt wire constants are part of the published contract.
fn receipt_constants_are_stable() {
    assert_eq!(rvm_context_wasm::receipt::receipt_encoded_size(), 352);
    assert_eq!(rvm_context_wasm::receipt::receipt_version(), 1);
    assert_eq!(rvm_context_wasm::contract_version(), 1);
}

const EXPECTED_RECORD_DIGESTS: [&str; 3] = [
    "d4353ecac0d4e0e6607dc518d04d4d7cabf3b4f06ba4b073b61086bf1a7f1271",
    "c58f5cc50515b847ec51a18df8d9f01925dc17486419472f66fab69a5bebaa71",
    "829d920fb412442b513816ac2d74a585a27a8a2a3498fa75c6d02869c5205ffe",
];
const EXPECTED_RECORD_BYTES: [&str; 3] = [
    "0000000000000000000000000000000001010000070000000807060504030201efbeadde010203040506070800000000cefaedfe090a0b0c0d0e0f1000000000",
    "0100000000000000e80300000000000002010000070000000807060504030201efbeadde010203040506070801000000cefaedfe090a0b0c0d0e0f1000000000",
    "0200000000000000d00700000000000007010000070000000807060504030201efbeadde010203040506070802000000cefaedfe090a0b0c0d0e0f1000000000",
];

fn all_checks() {
    canonical_uri_bytes_are_stable();
    builder_and_parser_agree();
    rights_bits_are_stable();
    view_mask_bits_are_stable();
    scope_containment_agrees();
    witness_record_digests_are_stable();
    receipt_constants_are_stable();
}

#[test]
fn determinism_native() {
    all_checks();
}

#[wasm_bindgen_test::wasm_bindgen_test]
fn determinism_wasm() {
    all_checks();
}
