use rvm_cap::{
    select_interruptible_prefix, AssessedAction, InterruptiblePrefixPolicy, PrefixAssessment,
    PrefixStopReason,
};
use std::process::Command;
use std::time::Instant;

const POLICY: [u8; 32] = [1; 32];
const EVALUATOR: [u8; 32] = [2; 32];
const OBSERVATION: [u8; 32] = [3; 32];
const SEEDS: [u64; 5] = [7, 17, 29, 43, 71];
const CASES_PER_SEED: usize = 2_000;
const BATCH: usize = 100;

#[derive(Clone, Copy)]
struct Expected {
    steps: u16,
    reason: PrefixStopReason,
}

fn policy() -> InterruptiblePrefixPolicy {
    InterruptiblePrefixPolicy {
        max_steps: 4,
        max_cumulative_risk_ppm: 120_000,
        max_step_risk_ppm: 60_000,
        max_observation_age_ticks: 10,
        required_capability_epoch: 7,
        policy_digest: POLICY,
        evaluator_digest: EVALUATOR,
    }
}

fn action(id: u8, risk: u32) -> AssessedAction {
    AssessedAction {
        action_digest: [id.max(1); 32],
        estimated_failure_risk_ppm: risk,
        precondition_met: true,
        reversible: true,
    }
}

fn scenario(kind: usize, nonce: u8) -> (InterruptiblePrefixPolicy, [AssessedAction; 4], PrefixAssessmentSeed, Expected) {
    let mut p = policy();
    let mut actions = [
        action(nonce, 20_000),
        action(nonce.wrapping_add(1), 20_000),
        action(nonce.wrapping_add(2), 20_000),
        action(nonce.wrapping_add(3), 20_000),
    ];
    let mut seed = PrefixAssessmentSeed {
        observation_tick: 100,
        observation_digest: OBSERVATION,
        capability_epoch: 7,
        policy_digest: POLICY,
        evaluator_digest: EVALUATOR,
        current_tick: 105,
        current_epoch: 7,
    };
    let expected = match kind {
        0 => Expected { steps: 4, reason: PrefixStopReason::Complete },
        1 => {
            seed.current_tick = 111;
            Expected { steps: 0, reason: PrefixStopReason::StaleObservation }
        }
        2 => {
            seed.current_epoch = 8;
            Expected { steps: 0, reason: PrefixStopReason::CapabilityEpochMismatch }
        }
        3 => {
            seed.policy_digest = [9; 32];
            Expected { steps: 0, reason: PrefixStopReason::PolicyMismatch }
        }
        4 => {
            seed.evaluator_digest = [8; 32];
            Expected { steps: 0, reason: PrefixStopReason::EvaluatorMismatch }
        }
        5 => {
            actions[1].precondition_met = false;
            Expected { steps: 1, reason: PrefixStopReason::PreconditionFailed }
        }
        6 => {
            actions[1].reversible = false;
            Expected { steps: 1, reason: PrefixStopReason::IrreversibleBoundary }
        }
        7 => {
            actions[0].estimated_failure_risk_ppm = 60_001;
            Expected { steps: 0, reason: PrefixStopReason::StepRisk }
        }
        8 => {
            actions = [
                action(nonce, 40_000),
                action(nonce.wrapping_add(1), 40_000),
                action(nonce.wrapping_add(2), 40_000),
                action(nonce.wrapping_add(3), 40_000),
            ];
            Expected { steps: 3, reason: PrefixStopReason::CumulativeRisk }
        }
        _ => {
            actions[0].action_digest = [0; 32];
            Expected { steps: 0, reason: PrefixStopReason::InvalidInput }
        }
    };
    if p.max_steps == 0 {
        p.max_steps = 4;
    }
    (p, actions, seed, expected)
}

#[derive(Clone, Copy)]
struct PrefixAssessmentSeed {
    observation_tick: u64,
    observation_digest: [u8; 32],
    capability_epoch: u64,
    policy_digest: [u8; 32],
    evaluator_digest: [u8; 32],
    current_tick: u64,
    current_epoch: u64,
}

fn percentile(mut values: Vec<u128>, percentile: usize) -> u128 {
    values.sort_unstable();
    let index = (values.len().saturating_sub(1) * percentile) / 100;
    values[index]
}

fn main() {
    let mut baseline_false_allow = 0_u64;
    let mut baseline_false_deny = 0_u64;
    let mut candidate_false_allow = 0_u64;
    let mut candidate_false_deny = 0_u64;
    let mut candidate_mismatch = 0_u64;
    let mut baseline_batch_ns = Vec::new();
    let mut candidate_batch_ns = Vec::new();
    let mut candidate_total_ns = 0_u128;
    let mut baseline_total_ns = 0_u128;
    let mut cases = 0_u64;

    for seed in SEEDS {
        let mut state = seed;
        let mut offset = 0_usize;
        while offset < CASES_PER_SEED {
            let batch_end = (offset + BATCH).min(CASES_PER_SEED);
            let baseline_start = Instant::now();
            for index in offset..batch_end {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let kind = (state as usize ^ index) % 10;
                let (_, actions, _, expected) = scenario(kind, state as u8);
                let baseline_steps = actions.len().min(4) as u16;
                if baseline_steps > expected.steps {
                    baseline_false_allow += 1;
                } else if baseline_steps < expected.steps {
                    baseline_false_deny += 1;
                }
            }
            let baseline_elapsed = baseline_start.elapsed().as_nanos();
            baseline_total_ns += baseline_elapsed;
            baseline_batch_ns.push(baseline_elapsed);

            state = seed;
            for index in 0..offset {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let _ = index;
            }
            let candidate_start = Instant::now();
            for index in offset..batch_end {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let kind = (state as usize ^ index) % 10;
                let (p, actions, seed_data, expected) = scenario(kind, state as u8);
                let assessment = PrefixAssessment {
                    observation_tick: seed_data.observation_tick,
                    observation_digest: seed_data.observation_digest,
                    capability_epoch: seed_data.capability_epoch,
                    policy_digest: seed_data.policy_digest,
                    evaluator_digest: seed_data.evaluator_digest,
                    actions: &actions,
                };
                let decision = select_interruptible_prefix(
                    &p,
                    &assessment,
                    seed_data.current_tick,
                    seed_data.current_epoch,
                );
                if decision.dispatch_steps > expected.steps {
                    candidate_false_allow += 1;
                } else if decision.dispatch_steps < expected.steps {
                    candidate_false_deny += 1;
                }
                if decision.dispatch_steps != expected.steps || decision.stop_reason != expected.reason {
                    candidate_mismatch += 1;
                }
                cases += 1;
            }
            let candidate_elapsed = candidate_start.elapsed().as_nanos();
            candidate_total_ns += candidate_elapsed;
            candidate_batch_ns.push(candidate_elapsed);
            offset = batch_end;
        }
    }

    let p50_ns = percentile(candidate_batch_ns.clone(), 50);
    let p95_ns = percentile(candidate_batch_ns, 95);
    let baseline_p50_ns = percentile(baseline_batch_ns.clone(), 50);
    let baseline_p95_ns = percentile(baseline_batch_ns, 95);
    let throughput = if candidate_total_ns == 0 {
        0.0
    } else {
        cases as f64 / (candidate_total_ns as f64 / 1_000_000_000.0)
    };
    let overhead_ratio = if baseline_total_ns == 0 {
        0.0
    } else {
        candidate_total_ns as f64 / baseline_total_ns as f64
    };
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());

    println!(
        "{{\n  \"schema\": \"rvm-interruptible-prefix-benchmark/v1\",\n  \"seeds\": {:?},\n  \"sample_size\": {},\n  \"batch_size\": {},\n  \"environment\": {{\"os\": \"{}\", \"arch\": \"{}\", \"rustc\": \"{}\"}},\n  \"baseline\": {{\"kind\": \"fixed-four-no-refresh\", \"false_allow\": {}, \"false_deny\": {}, \"total_ns\": {}, \"batch_p50_ns\": {}, \"batch_p95_ns\": {}}},\n  \"candidate\": {{\"false_allow\": {}, \"false_deny\": {}, \"decision_mismatch\": {}, \"total_ns\": {}, \"batch_p50_ns\": {}, \"batch_p95_ns\": {}, \"throughput_per_second\": {:.3}}},\n  \"relative_overhead_ratio\": {:.3},\n  \"dollar_cost_usd\": 0,\n  \"energy\": \"unmeasured\",\n  \"reproduction\": \"cargo run -p rvm-cap --example interruptible_prefix_bench --release\"\n}}",
        SEEDS,
        cases,
        BATCH,
        std::env::consts::OS,
        std::env::consts::ARCH,
        rustc.replace('"', "'"),
        baseline_false_allow,
        baseline_false_deny,
        baseline_total_ns,
        baseline_p50_ns,
        baseline_p95_ns,
        candidate_false_allow,
        candidate_false_deny,
        candidate_mismatch,
        candidate_total_ns,
        p50_ns,
        p95_ns,
        throughput,
        overhead_ratio,
    );

    assert_eq!(candidate_false_allow, 0, "candidate extended an unsafe prefix");
    assert_eq!(candidate_false_deny, 0, "candidate denied a safe prefix");
    assert_eq!(candidate_mismatch, 0, "candidate decision differed from frozen oracle");
}
