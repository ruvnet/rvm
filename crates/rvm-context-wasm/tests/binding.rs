//! Binding tests exercised on the real wasm32 target under Node.

use rvm_context::profile::{DerivedView as CoreDerived, ProfileView as CoreView};
use rvm_context::uri::{ProgressiveView, Revision};
use rvm_context_wasm::{ContextProfile, ContextScope, RuvUri, RuvUriBuilder, ViewMask};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const CANONICAL: &str = "ruv://context.example/acme/agent/researcher/memory";
const ZERO_REV: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const ONE_REV: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000001";

/// Reads the `code` property off a thrown JS error.
fn thrown_code(error: &JsValue) -> String {
    js_sys::Reflect::get(error, &JsValue::from_str("code"))
        .expect("error has a code property")
        .as_string()
        .expect("code is a string")
}

fn expect_rejection(text: &str, expected_code: &str) {
    let error = RuvUri::parse(text).err().unwrap_or_else(|| {
        panic!("expected {text} to be rejected as {expected_code}, but it parsed")
    });
    assert_eq!(thrown_code(&error), expected_code, "for input {text}");
    assert_eq!(
        rvm_context_wasm::ruv_uri_error(text).as_deref(),
        Some(expected_code),
        "non-throwing probe disagrees for {text}"
    );
    assert!(!rvm_context_wasm::is_ruv_uri(text));
}

#[wasm_bindgen_test]
fn canonical_uri_parses_into_components() {
    let uri = RuvUri::parse(CANONICAL).expect("canonical URI parses");
    assert_eq!(uri.authority(), "context.example");
    assert_eq!(uri.tenant(), "acme");
    assert_eq!(uri.subject_kind(), "agent");
    assert_eq!(uri.subject_id(), "researcher");
    assert_eq!(uri.collection(), "memory");
    assert!(uri.path().is_empty());
    assert_eq!(uri.revision(), None);
    assert_eq!(uri.view(), None);
    assert!(!uri.is_pinned());
}

#[wasm_bindgen_test]
fn full_uri_exposes_path_revision_and_view() {
    let text = format!(
        "ruv://context.example/acme/team/core/resources/Specs/API_v1?rev={ZERO_REV}&view=overview"
    );
    let uri = RuvUri::parse(&text).expect("full URI parses");
    assert_eq!(uri.path(), vec!["Specs".to_string(), "API_v1".to_string()]);
    assert_eq!(uri.revision().as_deref(), Some(ZERO_REV));
    assert_eq!(uri.view().as_deref(), Some("overview"));
    assert!(uri.is_pinned());
    assert_eq!(uri.subject_kind(), "team");
    assert_eq!(uri.collection(), "resources");
}

#[wasm_bindgen_test]
fn parse_format_round_trips_exactly() {
    let cases = [
        CANONICAL.to_string(),
        "ruv://context.example/acme/user/alice/skills/deploy".to_string(),
        format!("{CANONICAL}?rev={ZERO_REV}"),
        format!("{CANONICAL}?view=content"),
        format!("{CANONICAL}?rev={ZERO_REV}&view=abstract"),
        "ruv://a.b.c/t/service/api/resources/A/b-c/d.e/f_g/h~i".to_string(),
    ];
    for text in cases {
        let uri = RuvUri::parse(&text).expect("case parses");
        assert_eq!(uri.render(), text, "round trip changed the spelling");
        let again = RuvUri::parse(&uri.render()).expect("reparse succeeds");
        assert!(again.equals(&uri));
    }
}

#[wasm_bindgen_test]
fn each_rejection_class_reports_its_own_code() {
    expect_rejection(
        "ruv://context.example/ACME/agent/researcher/memory",
        "InvalidTenant",
    );
    expect_rejection(
        "ruv://context.example/acme/agent/researcher/memory/",
        "TrailingSlash",
    );
    expect_rejection(
        "ruv://context.example/acme/agent/researcher/memory/../secrets",
        "DotSegment",
    );
    expect_rejection(
        "ruv://context.example/acme/agent/researcher//memory",
        "EmptyPathSegment",
    );
    expect_rejection(
        "ruv://context.example/acme/agent/researcher/memory/a%2Fb",
        "PercentEncodingNotAllowed",
    );
    expect_rejection(
        "ruv://context.example/acme/agent/researcher/memory#section",
        "FragmentNotAllowed",
    );
    expect_rejection(
        "ruv://user:pw@context.example/acme/agent/researcher/memory",
        "CredentialsNotAllowed",
    );
    expect_rejection(
        "ruv://context.example:8443/acme/agent/researcher/memory",
        "PortNotAllowed",
    );
}

#[wasm_bindgen_test]
fn other_noncanonical_spellings_are_rejected() {
    expect_rejection("https://context.example/a/agent/b/memory", "InvalidScheme");
    expect_rejection(
        "ruv://context.example/acme/agent/researcher",
        "MissingComponent",
    );
    expect_rejection(
        "ruv://context.example/acme/Agent/researcher/memory",
        "InvalidSubjectKind",
    );
    expect_rejection(
        "ruv://context.example/acme/agent/researcher/Memory",
        "InvalidCollection",
    );
    expect_rejection(&format!("{CANONICAL}?rev=sha256:beef"), "InvalidRevision");
    expect_rejection(&format!("{CANONICAL}?view=Overview"), "InvalidView");
    expect_rejection(&format!("{CANONICAL}?depth=2"), "UnknownQueryKey");
    expect_rejection(
        &format!("{CANONICAL}?view=content&rev={ZERO_REV}"),
        "QueryOrder",
    );
}

#[wasm_bindgen_test]
fn thrown_errors_are_real_js_errors() {
    let error = RuvUri::parse("ruv://context.example/ACME/agent/researcher/memory")
        .err()
        .expect("rejected");
    assert!(error.is_instance_of::<js_sys::Error>());
    let error: js_sys::Error = error.unchecked_into();
    assert_eq!(error.name(), "RuvUriError");
    assert_eq!(
        String::from(error.message()),
        "invalid canonical tenant slug"
    );
}

#[wasm_bindgen_test]
fn builder_constructs_the_canonical_spelling() {
    let uri = RuvUriBuilder::new("context.example", "acme", "team", "core", "resources")
        .expect("components validate")
        .segment("Specs")
        .expect("segment validates")
        .segment("API_v1")
        .expect("segment validates")
        .revision(ZERO_REV)
        .expect("revision validates")
        .view("overview")
        .expect("view validates")
        .build()
        .expect("aggregate limits hold");
    assert_eq!(
        uri.render(),
        format!("ruv://context.example/acme/team/core/resources/Specs/API_v1?rev={ZERO_REV}&view=overview")
    );
}

#[wasm_bindgen_test]
fn builder_reports_the_component_that_failed() {
    let cases = [
        (
            ("Context.Example", "acme", "agent", "a", "memory"),
            "InvalidAuthority",
        ),
        (
            ("context.example", "ACME", "agent", "a", "memory"),
            "InvalidTenant",
        ),
        (
            ("context.example", "acme", "robot", "a", "memory"),
            "InvalidSubjectKind",
        ),
        (
            ("context.example", "acme", "agent", "-bad", "memory"),
            "InvalidSubjectId",
        ),
        (
            ("context.example", "acme", "agent", "a", "notes"),
            "InvalidCollection",
        ),
    ];
    for ((authority, tenant, kind, id, collection), code) in cases {
        let error = RuvUriBuilder::new(authority, tenant, kind, id, collection)
            .err()
            .unwrap_or_else(|| panic!("expected {code}"));
        assert_eq!(thrown_code(&error), code);
    }
}

#[wasm_bindgen_test]
fn builder_values_are_reusable_across_branches() {
    let base = RuvUriBuilder::new("context.example", "acme", "agent", "researcher", "memory")
        .expect("components validate");
    let first = base
        .segment("alpha")
        .expect("segment")
        .build()
        .expect("build");
    let second = base
        .segment("beta")
        .expect("segment")
        .build()
        .expect("build");
    assert_eq!(first.render(), format!("{CANONICAL}/alpha"));
    assert_eq!(second.render(), format!("{CANONICAL}/beta"));
}

#[wasm_bindgen_test]
fn with_revision_and_with_view_extend_a_parsed_uri() {
    let uri = RuvUri::parse(CANONICAL).expect("parses");
    let pinned = uri.with_revision(ZERO_REV).expect("revision validates");
    assert!(pinned.is_pinned());
    assert_eq!(pinned.render(), format!("{CANONICAL}?rev={ZERO_REV}"));

    let viewed = pinned.with_view("content").expect("view validates");
    assert_eq!(
        viewed.render(),
        format!("{CANONICAL}?rev={ZERO_REV}&view=content")
    );

    assert_eq!(
        thrown_code(&uri.with_revision("sha256:zz").err().expect("rejected")),
        "InvalidRevision"
    );
    assert_eq!(
        thrown_code(&uri.with_view("full").err().expect("rejected")),
        "InvalidView"
    );
}

#[wasm_bindgen_test]
fn view_masks_compose_and_reject_reserved_bits() {
    let all = ViewMask::all();
    let content = ViewMask::view("content").expect("view name");
    let abstract_only = ViewMask::view("abstract").expect("view name");

    assert!(all.contains(&content));
    assert!(!content.contains(&all));
    assert!(all.allows("overview").expect("view name"));
    assert!(!abstract_only.allows("content").expect("view name"));

    let combined = content.union(&abstract_only);
    assert!(combined.contains(&content));
    assert!(combined.contains(&abstract_only));
    assert_eq!(
        ViewMask::from_bits(combined.bits())
            .expect("round trips")
            .bits(),
        combined.bits()
    );

    assert_eq!(
        thrown_code(&ViewMask::from_bits(0).err().expect("rejected")),
        "InvalidViewMask"
    );
    assert_eq!(
        thrown_code(&ViewMask::from_bits(0x10).err().expect("rejected")),
        "InvalidViewMask"
    );
    assert_eq!(
        thrown_code(&ViewMask::view("raw").err().expect("rejected")),
        "InvalidView"
    );
}

#[wasm_bindgen_test]
fn scope_containment_follows_the_path_prefix() {
    let parent_uri = RuvUri::parse(&format!("{CANONICAL}/projects")).expect("parses");
    let child_uri = RuvUri::parse(&format!("{CANONICAL}/projects/atlas")).expect("parses");
    let other_uri = RuvUri::parse(&format!("{CANONICAL}/archive")).expect("parses");

    let parent = ContextScope::from_uri(&parent_uri, &ViewMask::all());
    let child = ContextScope::from_uri(&child_uri, &ViewMask::all());
    let other = ContextScope::from_uri(&other_uri, &ViewMask::all());

    assert!(parent.contains_scope(&child));
    assert!(!child.contains_scope(&parent));
    assert!(!parent.contains_scope(&other));

    assert_eq!(parent.authority(), "context.example");
    assert_eq!(parent.tenant(), "acme");
    assert_eq!(parent.subject_kind(), "agent");
    assert_eq!(parent.subject_id(), "researcher");
    assert_eq!(parent.collection(), "memory");
    assert_eq!(parent.path_prefix(), vec!["projects".to_string()]);

    // A narrower view mask is contained; a wider one is not.
    let narrow = ContextScope::from_uri(&child_uri, &ViewMask::view("abstract").expect("view"));
    assert!(parent.contains_scope(&narrow));
    let wide = ContextScope::from_uri(&parent_uri, &ViewMask::view("abstract").expect("view"));
    assert!(!wide.contains_scope(&child));
}

#[wasm_bindgen_test]
fn scope_ignores_the_revision_and_view_of_its_root() {
    let plain = RuvUri::parse(&format!("{CANONICAL}/notes")).expect("parses");
    let decorated =
        RuvUri::parse(&format!("{CANONICAL}/notes?rev={ZERO_REV}&view=content")).expect("parses");
    let a = ContextScope::from_uri(&plain, &ViewMask::all());
    let b = ContextScope::from_uri(&decorated, &ViewMask::all());
    assert!(a.contains_scope(&b));
    assert!(b.contains_scope(&a));
}

fn sample_profile_bytes() -> Vec<u8> {
    let content_digest = Revision::sha256([1_u8; 32]);
    let provenance = CoreDerived::new(
        content_digest,
        Revision::sha256([2_u8; 32]),
        Revision::sha256([3_u8; 32]),
        Revision::sha256([4_u8; 32]),
        Revision::sha256([5_u8; 32]),
    )
    .expect("provenance digests are nonzero");
    let views = vec![
        CoreView::content(10, content_digest).expect("content view"),
        CoreView::derived(
            ProgressiveView::Abstract,
            11,
            Revision::sha256([6_u8; 32]),
            provenance,
        )
        .expect("abstract view"),
    ];
    rvm_context::profile::ContextProfile::new(views)
        .expect("profile validates")
        .to_bytes()
}

#[wasm_bindgen_test]
fn profile_decodes_and_round_trips() {
    let bytes = sample_profile_bytes();
    let profile = ContextProfile::decode(&bytes).expect("payload decodes");
    assert_eq!(profile.to_bytes(), bytes, "re-encode is not byte identical");

    let views = profile.views();
    assert_eq!(views.len(), 2);
    assert_eq!(views[0].view(), "abstract");
    assert_eq!(views[1].view(), "content");

    let content = profile
        .view("content")
        .expect("view name")
        .expect("content view is present");
    assert_eq!(content.segment_id(), 10);
    assert_eq!(
        content.payload(),
        "sha256:0101010101010101010101010101010101010101010101010101010101010101"
    );
    assert!(content.provenance().is_none());

    let derived = profile
        .view("abstract")
        .expect("view name")
        .expect("abstract view is present");
    let provenance = derived
        .provenance()
        .expect("derived views carry provenance");
    assert_eq!(provenance.source(), content.payload());
    assert_eq!(
        provenance.generator(),
        "sha256:0202020202020202020202020202020202020202020202020202020202020202"
    );

    assert!(profile.view("overview").expect("view name").is_none());
}

#[wasm_bindgen_test]
fn profile_rejects_corrupt_payloads() {
    let bytes = sample_profile_bytes();

    let mut wrong_magic = bytes.clone();
    wrong_magic[0] = b'X';
    assert_eq!(
        thrown_code(
            &ContextProfile::decode(&wrong_magic)
                .err()
                .expect("rejected")
        ),
        "Encoding"
    );

    let truncated = &bytes[..bytes.len() - 1];
    assert_eq!(
        thrown_code(&ContextProfile::decode(truncated).err().expect("rejected")),
        "Encoding"
    );

    assert_eq!(
        thrown_code(&ContextProfile::decode(&[]).err().expect("rejected")),
        "Encoding"
    );
}

#[wasm_bindgen_test]
fn contract_version_is_exposed() {
    assert_eq!(rvm_context_wasm::contract_version(), 1);
}

#[wasm_bindgen_test]
fn distinct_revisions_produce_distinct_uris() {
    let base = RuvUri::parse(CANONICAL).expect("parses");
    let a = base.with_revision(ZERO_REV).expect("revision");
    let b = base.with_revision(ONE_REV).expect("revision");
    assert!(!a.equals(&b));
    assert_ne!(a.render(), b.render());
}

// ---------------------------------------------------------------------------
// Governed runtime
//
// These are wasm-only because every rejection path constructs a JsValue.
// ---------------------------------------------------------------------------

use rvm_context_wasm::{ContextRuntime, EpochCommitments, Rights};

const BASE: &str = "ruv://context.example/acme/agent/researcher/memory";

fn runtime_with_root(
    scope_uri: &str,
    operations: &[&str],
) -> (ContextRuntime, rvm_context_wasm::CapabilityHandle) {
    let mut runtime = ContextRuntime::new(7).expect("actor in range");
    let root = RuvUri::parse(scope_uri).expect("scope root parses");
    let scope = ContextScope::from_uri(&root, &ViewMask::all());
    let rights = Rights::for_operations(operations.iter().map(|op| (*op).into()).collect())
        .expect("registered operations");
    let handle = runtime
        .issue_root(&scope, &rights, 7)
        .expect("root capability issues");
    (runtime, handle)
}

#[wasm_bindgen_test]
fn runtime_issues_and_revokes_a_root_capability() {
    let (mut runtime, handle) = runtime_with_root(BASE, &["resolve", "read"]);
    assert_eq!(runtime.actor(), 7);
    // The generation is an opaque staleness counter; only its role matters,
    // which `a_stale_handle_is_refused_after_revocation` covers.
    let felled = runtime.revoke(&handle).expect("revocation succeeds");
    assert!(felled >= 1, "revoking a root should fell at least itself");
}

#[wasm_bindgen_test]
fn a_stale_handle_is_refused_after_revocation() {
    let (mut runtime, handle) = runtime_with_root(BASE, &["resolve"]);
    runtime.revoke(&handle).expect("revocation succeeds");
    let target = RuvUri::parse(BASE).expect("parses");
    let error = runtime
        .resolve(&handle, &target)
        .err()
        .expect("a revoked handle must not resolve");
    assert_eq!(thrown_code(&error), "AccessDenied");
}

#[wasm_bindgen_test]
fn a_cross_tenant_reach_is_refused() {
    let (mut runtime, handle) = runtime_with_root(BASE, &["resolve", "read"]);
    // Same shape, different tenant.
    let other_tenant =
        RuvUri::parse("ruv://context.example/other/agent/researcher/memory").expect("parses");
    let error = runtime
        .resolve(&handle, &other_tenant)
        .err()
        .expect("a cross-tenant reach must be refused");
    assert_eq!(thrown_code(&error), "AccessDenied");

    // Same tenant, different subject.
    let other_subject =
        RuvUri::parse("ruv://context.example/acme/agent/other/memory").expect("parses");
    assert_eq!(
        thrown_code(
            &runtime
                .resolve(&handle, &other_subject)
                .err()
                .expect("refused")
        ),
        "AccessDenied"
    );

    // Same subject, different collection.
    let other_collection =
        RuvUri::parse("ruv://context.example/acme/agent/researcher/skills").expect("parses");
    assert_eq!(
        thrown_code(
            &runtime
                .resolve(&handle, &other_collection)
                .err()
                .expect("refused")
        ),
        "AccessDenied"
    );
}

#[wasm_bindgen_test]
fn a_reach_outside_the_path_prefix_is_refused_at_the_last_segment() {
    // The scope is pinned three segments deep. The violating segment is at the
    // LAST prefix position: a containment check inside a short-circuiting loop
    // would pass position 1 and still be wrong here.
    let (mut runtime, handle) = runtime_with_root(&format!("{BASE}/a/b/c"), &["resolve"]);

    let diverges_last = RuvUri::parse(&format!("{BASE}/a/b/X")).expect("parses");
    assert_eq!(
        thrown_code(
            &runtime
                .resolve(&handle, &diverges_last)
                .err()
                .expect("divergence at the last prefix segment must be refused")
        ),
        "AccessDenied"
    );

    let diverges_middle = RuvUri::parse(&format!("{BASE}/a/X/c")).expect("parses");
    assert_eq!(
        thrown_code(
            &runtime
                .resolve(&handle, &diverges_middle)
                .err()
                .expect("divergence in the middle must be refused")
        ),
        "AccessDenied"
    );

    // A strict ancestor of the scope is also outside it.
    let ancestor = RuvUri::parse(&format!("{BASE}/a/b")).expect("parses");
    assert_eq!(
        thrown_code(&runtime.resolve(&handle, &ancestor).err().expect("refused")),
        "AccessDenied"
    );
}

#[wasm_bindgen_test]
fn rights_are_enforced_per_operation() {
    // Read-only rights must not authorize a write.
    let (mut runtime, handle) = runtime_with_root(BASE, &["resolve"]);
    let pinned = RuvUri::parse(&format!("{BASE}?rev={ZERO_REV}")).expect("parses");
    let error = runtime
        .put(&handle, &pinned, &[0_u8; 8])
        .err()
        .expect("a read-only capability must not put");
    assert_eq!(thrown_code(&error), "AccessDenied");
}

#[wasm_bindgen_test]
fn delegation_cannot_widen_the_parent_scope() {
    let (mut runtime, handle) = runtime_with_root(&format!("{BASE}/a/b"), &["resolve", "grant"]);

    // Widening the path prefix upward must be refused.
    let wider = ContextScope::from_uri(
        &RuvUri::parse(&format!("{BASE}/a")).expect("parses"),
        &ViewMask::all(),
    );
    let rights = Rights::for_operation("resolve").expect("registered");
    let error = runtime
        .delegate(&handle, &wider, &rights, 7)
        .err()
        .expect("widening the scope must be refused");
    assert_eq!(thrown_code(&error), "ScopeEscalation");

    // Narrowing is allowed.
    let narrower = ContextScope::from_uri(
        &RuvUri::parse(&format!("{BASE}/a/b/c")).expect("parses"),
        &ViewMask::all(),
    );
    let child = runtime
        .delegate(&handle, &narrower, &rights, 7)
        .expect("narrowing delegation succeeds");
    assert!(child.index() != handle.index() || child.generation() != handle.generation());
}

#[wasm_bindgen_test]
fn delegation_cannot_widen_the_view_mask() {
    let narrow_views = ViewMask::view("abstract").expect("view");
    let mut runtime = ContextRuntime::new(7).expect("actor in range");
    let root = RuvUri::parse(BASE).expect("parses");
    let scope = ContextScope::from_uri(&root, &narrow_views);
    let rights = Rights::for_operations(vec!["resolve".into(), "grant".into()]).expect("rights");
    let handle = runtime.issue_root(&scope, &rights, 7).expect("root issues");

    let wider = ContextScope::from_uri(&root, &ViewMask::all());
    let error = runtime
        .delegate(&handle, &wider, &rights, 7)
        .err()
        .expect("widening the view mask must be refused");
    assert_eq!(thrown_code(&error), "ScopeEscalation");
}

#[wasm_bindgen_test]
fn the_witness_log_records_decisions_and_verifies() {
    let (mut runtime, handle) = runtime_with_root(BASE, &["resolve", "read"]);
    let before = runtime.witness_sequence();

    let outside =
        RuvUri::parse("ruv://context.example/other/agent/researcher/memory").expect("parses");
    let _ = runtime.resolve(&handle, &outside);
    let target = RuvUri::parse(BASE).expect("parses");
    let _ = runtime.resolve(&handle, &target);

    let after = runtime.witness_sequence();
    assert!(
        after > before,
        "governed decisions must advance the witness sequence: {before} -> {after}"
    );
    assert_eq!(
        runtime.witness_record_count() as u64,
        after,
        "retained record count should match the sequence for a short session"
    );

    // The keyless chain check must pass over the module's own log.
    let verified = runtime
        .verify_witness_chain()
        .expect("the module's own chain verifies");
    assert_eq!(verified as u64, after);

    // Digests are 32 bytes each and cover every retained record.
    let digests = runtime.witness_digests();
    assert_eq!(digests.len(), runtime.witness_record_count() * 32);
}

#[wasm_bindgen_test]
fn the_logical_clock_makes_sessions_reproducible() {
    let first = scripted_witness_digests();
    let second = scripted_witness_digests();
    assert_eq!(
        first, second,
        "two identical sessions must produce identical witness digests"
    );
    assert!(!first.is_empty(), "the session recorded nothing");
}

fn scripted_witness_digests() -> Vec<u8> {
    let (mut runtime, handle) = runtime_with_root(BASE, &["resolve", "read"]);
    let outside =
        RuvUri::parse("ruv://context.example/other/agent/researcher/memory").expect("parses");
    let _ = runtime.resolve(&handle, &outside);
    runtime.witness_digests()
}

#[wasm_bindgen_test]
fn rights_names_round_trip() {
    let rights = Rights::from_names(vec!["read".into(), "write".into(), "prove".into()])
        .expect("known rights");
    assert_eq!(rights.names(), vec!["read", "write", "prove"]);
    assert_eq!(
        thrown_code(
            &Rights::from_names(vec!["admin".into()])
                .err()
                .expect("rejected")
        ),
        "UnknownRight"
    );
    assert_eq!(
        thrown_code(&Rights::for_operation("teleport").err().expect("rejected")),
        "UnknownOperation"
    );
}

#[wasm_bindgen_test]
fn an_out_of_range_partition_is_refused() {
    let error = ContextRuntime::new(4096).err().expect("rejected");
    assert_eq!(thrown_code(&error), "InvalidPartitionId");
    assert!(ContextRuntime::new(4095).is_ok());
}

#[wasm_bindgen_test]
fn receipt_verification_requires_a_thirty_two_byte_key() {
    let (mut runtime, handle) = runtime_with_root(BASE, &["resolve", "sealReceipt"]);
    let target = RuvUri::parse(BASE).expect("parses");
    let _ = runtime.resolve(&handle, &target);
    let commitments = EpochCommitments::new(&[0; 32], &[0; 32], &[0; 32], &[0; 32])
        .expect("32-byte roots are accepted");
    let error = runtime
        .seal_epoch(&handle, &target, &[0_u8; 8], &commitments)
        .err()
        .expect("a short key must be refused");
    assert_eq!(thrown_code(&error), "InvalidKeyLength");

    // A commitment of the wrong length names the field that was wrong.
    let error = EpochCommitments::new(&[0; 32], &[0; 31], &[0; 32], &[0; 32])
        .err()
        .expect("a short root must be refused");
    assert_eq!(thrown_code(&error), "InvalidDigestLength");
}

#[wasm_bindgen_test]
fn capacities_are_published() {
    let capacities = ContextRuntime::capacities();
    assert_eq!(capacities, vec![64_u32, 64, 1024, 64, 64]);
}
