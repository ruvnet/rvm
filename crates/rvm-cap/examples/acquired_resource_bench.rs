//! Deterministic structural benchmark for acquired-resource activation.
//!
//! This benchmark intentionally compares the activation boundary with a weak
//! provider-evidence-only baseline. It does not claim task-level improvement.

use rvm_cap::{
    AcquiredResourceKind, ActivationEnvelope, ActivationLedger, CapRights, CapType, Digest32,
    ProviderEvidenceVerifier, QuarantinedResource, ResolvedResourceManifest,
};
use std::hint::black_box;
use std::time::Instant;

const CASES: usize = 10_000;
const BATCH: usize = 100;
const SEEDS: [u64; 5] = [7, 17, 31, 47, 73];
const PRINCIPAL: Digest32 = [1; 32];
const PURPOSE: Digest32 = [2; 32];
const PROVIDER: Digest32 = [3; 32];
const EVIDENCE: Digest32 = [4; 32];

struct Verifier;

impl ProviderEvidenceVerifier for Verifier {
    fn resolver_version(&self) -> u32 {
        9
    }

    fn verify(&self, _manifest: &ResolvedResourceManifest) -> bool {
        true
    }
}

fn envelope() -> ActivationEnvelope {
    ActivationEnvelope {
        principal_digest: PRINCIPAL,
        purpose_digest: PURPOSE,
        provider_digest: PROVIDER,
        allowed_kind: AcquiredResourceKind::Service,
        allowed_cap_type: CapType::Context,
        allowed_rights: CapRights::READ | CapRights::EXECUTE,
        resolver_version: 9,
        policy_epoch: 101,
        provider_epoch: 103,
        graph_epoch: 107,
        max_delegation_depth: 1,
        max_effects: 10,
        max_data_bytes: 4_096,
        max_children: 4,
        max_evidence_age_ms: 1_000,
        expires_at_ms: 20_000,
    }
}

fn manifest(resource_id: u64) -> ResolvedResourceManifest {
    ResolvedResourceManifest {
        resource_id,
        kind: AcquiredResourceKind::Service,
        requested_cap_type: CapType::Context,
        requested_rights: CapRights::READ,
        principal_digest: PRINCIPAL,
        purpose_digest: PURPOSE,
        provider_digest: PROVIDER,
        evidence_digest: EVIDENCE,
        resolver_version: 9,
        policy_epoch: 101,
        provider_epoch: 103,
        graph_epoch: 107,
        delegation_depth: 1,
        effect_budget: 1,
        data_budget_bytes: 128,
        child_budget: 1,
        resolved_at_ms: 10_000,
    }
}

fn mutate_hostile(case_index: usize, mut item: ResolvedResourceManifest) -> ResolvedResourceManifest {
    match case_index % 5 {
        0 => item.requested_rights = CapRights::READ | CapRights::WRITE,
        1 => item.graph_epoch = 106,
        2 => item.provider_digest = [8; 32],
        3 => item.resolved_at_ms = 8_000,
        _ => item.effect_budget = 11,
    }
    item
}

fn percentile_95(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    let rank = values.len().saturating_mul(95).div_ceil(100);
    values[rank.saturating_sub(1)]
}

fn integer_variance(values: &[u128]) -> u128 {
    let count = values.len() as u128;
    let mean = values.iter().copied().sum::<u128>() / count;
    values
        .iter()
        .map(|value| {
            let delta = value.abs_diff(mean);
            delta.saturating_mul(delta)
        })
        .sum::<u128>()
        / count
}

fn main() {
    let verifier = Verifier;
    let env = envelope();
    let mut baseline_accepts = 0usize;
    let baseline_start = Instant::now();

    for seed in SEEDS {
        for offset in 0..(CASES / SEEDS.len()) {
            let global = offset + usize::try_from(seed).expect("seed fits usize");
            let hostile = global % 2 == 1;
            let base = manifest(seed.saturating_mul(10_000) + u64::try_from(offset).expect("offset fits"));
            let item = if hostile {
                mutate_hostile(global, base)
            } else {
                base
            };
            if black_box(verifier.verify(black_box(&item))) {
                baseline_accepts += 1;
            }
        }
    }
    let baseline_elapsed = baseline_start.elapsed().as_nanos();

    let mut clean_accepts = 0usize;
    let mut hostile_rejects = 0usize;
    let mut false_accepts = 0usize;
    let mut false_denials = 0usize;
    let mut batch_latencies = Vec::with_capacity(CASES / BATCH);
    let candidate_start = Instant::now();
    let mut batch_start = Instant::now();
    let mut processed = 0usize;

    for seed in SEEDS {
        for offset in 0..(CASES / SEEDS.len()) {
            let global = offset + usize::try_from(seed).expect("seed fits usize");
            let hostile = global % 2 == 1;
            let base = manifest(seed.saturating_mul(10_000) + u64::try_from(offset).expect("offset fits"));
            let item = if hostile {
                mutate_hostile(global, base)
            } else {
                base
            };
            let resource = QuarantinedResource::new(item);
            let mut ledger = ActivationLedger::new(&env);
            let accepted = black_box(
                resource
                    .activate(1, 10_500, &env, &mut ledger, &verifier)
                    .is_ok(),
            );

            if hostile {
                if accepted {
                    false_accepts += 1;
                } else {
                    hostile_rejects += 1;
                }
            } else if accepted {
                clean_accepts += 1;
            } else {
                false_denials += 1;
            }

            processed += 1;
            if processed % BATCH == 0 {
                batch_latencies.push(batch_start.elapsed().as_nanos());
                batch_start = Instant::now();
            }
        }
    }

    let candidate_elapsed = candidate_start.elapsed().as_nanos();
    let mut p95_input = batch_latencies.clone();
    let p95_batch_ns = percentile_95(&mut p95_input);
    let variance_batch_ns2 = integer_variance(&batch_latencies);
    let mean_decision_ns = candidate_elapsed / CASES as u128;
    let throughput_per_second = (CASES as u128).saturating_mul(1_000_000_000) / candidate_elapsed.max(1);
    let relative_overhead_percent = candidate_elapsed.saturating_mul(100) / baseline_elapsed.max(1);

    println!("acquired_resource_activation_benchmark");
    println!("cases={CASES}");
    println!("seeds={SEEDS:?}");
    println!("baseline=provider_evidence_only");
    println!("candidate=quarantine_plus_activation_envelope");
    println!("baseline_accepts={baseline_accepts}");
    println!("clean_accepts={clean_accepts}");
    println!("hostile_rejects={hostile_rejects}");
    println!("false_accepts={false_accepts}");
    println!("false_denials={false_denials}");
    println!("baseline_total_ns={baseline_elapsed}");
    println!("candidate_total_ns={candidate_elapsed}");
    println!("candidate_mean_decision_ns={mean_decision_ns}");
    println!("candidate_p95_batch_100_ns={p95_batch_ns}");
    println!("candidate_batch_variance_ns2={variance_batch_ns2}");
    println!("candidate_throughput_per_second={throughput_per_second}");
    println!("relative_runtime_percent_of_baseline={relative_overhead_percent}");
    println!("local_model_cost_usd=0");
    println!("energy_measured=false");

    assert_eq!(baseline_accepts, CASES);
    assert_eq!(clean_accepts, CASES / 2);
    assert_eq!(hostile_rejects, CASES / 2);
    assert_eq!(false_accepts, 0);
    assert_eq!(false_denials, 0);
    assert!(!QuarantinedResource::new(manifest(1))
        .activate(
            1,
            10_500,
            &env,
            &mut ActivationLedger::new(&env),
            &verifier,
        )
        .expect("clean activation")
        .grants_authority());
}