//! GPU subsystem performance benchmarks.
//!
//! All GPU operations should be < 100ns as they are in the scheduling
//! hot path. These benchmarks verify budget checks, context creation,
//! launch config validation, queue operations, and epoch resets.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use rvm_gpu::{
    GpuBudget, GpuContext, GpuStatus,
    kernel::{KernelId, LaunchConfig},
    queue::{GpuQueue, QueueCommand, QueueId},
    DEFAULT_KERNEL_TIMEOUT_NS,
};
use rvm_types::PartitionId;

// ---------------------------------------------------------------------------
// Benchmark 1: GPU budget check/record cycle
// Target: < 100 ns
// ---------------------------------------------------------------------------
fn bench_gpu_budget_check(c: &mut Criterion) {
    c.bench_function("gpu_budget_check_compute", |b| {
        let budget = GpuBudget::new(u64::MAX, 0, 0, 0);
        b.iter(|| {
            let _ = black_box(budget.check_compute(1000));
        });
    });

    c.bench_function("gpu_budget_record_compute", |b| {
        b.iter_custom(|iters| {
            let mut budget = GpuBudget::new(u64::MAX, u64::MAX, u64::MAX, u32::MAX);
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = black_box(budget.record_compute(1));
            }
            start.elapsed()
        });
    });

    c.bench_function("gpu_budget_check_and_record_cycle", |b| {
        b.iter_custom(|iters| {
            let mut budget = GpuBudget::new(u64::MAX, u64::MAX, u64::MAX, u32::MAX);
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = black_box(budget.check_compute(100));
                let _ = black_box(budget.record_compute(100));
                let _ = black_box(budget.check_transfer(50));
                let _ = black_box(budget.record_transfer(50));
                let _ = black_box(budget.check_launch());
                let _ = black_box(budget.record_launch());
            }
            start.elapsed()
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 2: GPU context creation
// Target: < 100 ns
// ---------------------------------------------------------------------------
fn bench_gpu_context_create(c: &mut Criterion) {
    c.bench_function("gpu_context_create", |b| {
        let pid = PartitionId::new(1);
        let budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
        b.iter(|| {
            black_box(GpuContext::new(pid, 0, budget));
        });
    });

    c.bench_function("gpu_context_is_ready", |b| {
        let budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
        let mut ctx = GpuContext::new(PartitionId::new(1), 0, budget);
        ctx.status = GpuStatus::Ready;
        b.iter(|| {
            black_box(ctx.is_ready());
        });
    });

    c.bench_function("gpu_context_check_budget", |b| {
        let budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
        let ctx = GpuContext::new(PartitionId::new(1), 0, budget);
        b.iter(|| {
            let _ = black_box(ctx.check_budget(1000, 512));
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 3: Launch config validation (hot path)
// Target: < 100 ns
// ---------------------------------------------------------------------------
fn bench_gpu_launch_config_validate(c: &mut Criterion) {
    c.bench_function("gpu_launch_config_validate_default", |b| {
        let cfg = LaunchConfig::default();
        b.iter(|| {
            let _ = black_box(cfg.validate());
        });
    });

    c.bench_function("gpu_launch_config_validate_3d", |b| {
        let cfg = LaunchConfig {
            workgroups: [8, 8, 4],
            workgroup_size: [32, 8, 4],
            shared_memory_bytes: 16384,
            timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
        };
        b.iter(|| {
            let _ = black_box(cfg.validate());
        });
    });

    c.bench_function("gpu_launch_config_total_threads", |b| {
        let cfg = LaunchConfig {
            workgroups: [256, 256, 1],
            workgroup_size: [256, 1, 1],
            shared_memory_bytes: 0,
            timeout_ns: DEFAULT_KERNEL_TIMEOUT_NS,
        };
        b.iter(|| {
            black_box(cfg.total_threads());
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 4: Queue enqueue/dequeue
// Target: < 100 ns per operation
// ---------------------------------------------------------------------------
fn bench_gpu_queue_enqueue(c: &mut Criterion) {
    c.bench_function("gpu_queue_enqueue_barrier", |b| {
        b.iter_custom(|iters| {
            let mut q = GpuQueue::with_max_depth(
                QueueId::new(0),
                PartitionId::new(1),
                iters as u32 + 1,
            );
            let cmd = QueueCommand::barrier();
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = black_box(q.enqueue(&cmd));
            }
            start.elapsed()
        });
    });

    c.bench_function("gpu_queue_enqueue_kernel_launch", |b| {
        b.iter_custom(|iters| {
            let mut q = GpuQueue::with_max_depth(
                QueueId::new(0),
                PartitionId::new(1),
                iters as u32 + 1,
            );
            let cmd = QueueCommand::kernel_launch(KernelId::new(1));
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = black_box(q.enqueue(&cmd));
            }
            start.elapsed()
        });
    });

    c.bench_function("gpu_queue_enqueue_complete_cycle", |b| {
        let mut q = GpuQueue::with_max_depth(
            QueueId::new(0),
            PartitionId::new(1),
            256,
        );
        let cmd = QueueCommand::barrier();
        b.iter(|| {
            let _ = q.enqueue(&cmd);
            let _ = q.complete_one();
            black_box(q.pending());
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 5: Budget epoch reset
// Target: < 100 ns
// ---------------------------------------------------------------------------
fn bench_gpu_budget_reset(c: &mut Criterion) {
    c.bench_function("gpu_budget_reset_epoch", |b| {
        let mut budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
        budget.record_compute(5_000_000).unwrap();
        budget.record_transfer(2_000_000).unwrap();
        for _ in 0..50 {
            budget.record_launch().unwrap();
        }
        budget.record_memory(524_288).unwrap();

        b.iter(|| {
            let mut b = budget;
            b.reset_epoch();
            black_box(b);
        });
    });

    c.bench_function("gpu_context_reset_epoch", |b| {
        let budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
        let mut ctx = GpuContext::new(PartitionId::new(1), 0, budget);
        ctx.status = GpuStatus::Ready;
        ctx.record_kernel_launch(5_000_000).unwrap();
        ctx.record_transfer(2_000_000).unwrap();
        ctx.record_memory_alloc(524_288).unwrap();

        b.iter(|| {
            let mut c = ctx;
            c.reset_epoch();
            black_box(c);
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark 6: Budget remaining queries (read-only hot path)
// ---------------------------------------------------------------------------
fn bench_gpu_budget_remaining(c: &mut Criterion) {
    c.bench_function("gpu_budget_remaining_all", |b| {
        let mut budget = GpuBudget::new(10_000_000, 1_048_576, 4_194_304, 100);
        budget.record_compute(3_000_000).unwrap();
        budget.record_memory(512_000).unwrap();
        budget.record_transfer(1_000_000).unwrap();

        b.iter(|| {
            black_box(budget.remaining_compute());
            black_box(budget.remaining_memory());
            black_box(budget.remaining_transfer());
            black_box(budget.is_exhausted());
        });
    });
}

criterion_group!(
    benches,
    bench_gpu_budget_check,
    bench_gpu_context_create,
    bench_gpu_launch_config_validate,
    bench_gpu_queue_enqueue,
    bench_gpu_budget_reset,
    bench_gpu_budget_remaining,
);
criterion_main!(benches);
