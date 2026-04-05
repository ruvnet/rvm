# Quick Start: Your First RVM Build in 5 Minutes

This guide takes you from zero to a booted RVM instance in five steps. By the end you will have compiled every crate, run the test suite, executed benchmarks, booted the kernel on a virtual AArch64 machine, and explored the public API.

---

## Prerequisites

You need four things on your machine before you start.

**1. Rust 1.77 or later**

```bash
rustup update stable
rustc --version   # should print 1.77.0 or higher
```

**2. AArch64 bare-metal target**

```bash
rustup target add aarch64-unknown-none
```

**3. cargo-binutils (for binary conversion)**

```bash
cargo install cargo-binutils
rustup component add llvm-tools
```

**4. QEMU (for running the kernel)**

```bash
# macOS
brew install qemu

# Ubuntu / Debian
sudo apt install qemu-system-aarch64

# Verify
qemu-system-aarch64 --version   # should print 8.0 or higher
```

---

## Step 1: Clone and Build

Clone the repository and verify that all 648 tests pass on your host machine:

```bash
git clone https://github.com/ruvnet/rvm.git
cd rvm

# Run all library tests across the workspace
cargo test --workspace --lib
```

This command compiles every crate (`rvm-types`, `rvm-hal`, `rvm-cap`, `rvm-witness`, `rvm-proof`, `rvm-partition`, `rvm-sched`, `rvm-memory`, `rvm-coherence`, `rvm-boot`, `rvm-wasm`, `rvm-security`, `rvm-kernel`) and their integration tests. All crates are `#![no_std]` but include conditional `std` support for host testing.

You should see output ending with:

```
test result: ok. 648 passed; 0 failed; 0 ignored
```

> **Tip:** If a test fails, check [Troubleshooting](14-troubleshooting.md) for common host-build issues.

---

## Step 2: Run Benchmarks

RVM ships with 21 criterion benchmarks covering every performance-critical path:

```bash
cargo bench -p rvm-benches
```

This produces HTML reports in `target/criterion/`. Key benchmarks to look at:

| Benchmark | What It Measures | ADR Target | Typical Result |
|-----------|-----------------|-----------|----------------|
| `witness_emit` | Time to emit a 64-byte witness record | < 500 ns | ~17 ns |
| `p1_verify` | P1 capability check latency | < 1 us | < 1 ns |
| `p2_pipeline` | Full P2 proof pipeline | < 100 us | ~996 ns |
| `partition_switch` | Context switch stub | < 10 us | ~6 ns |
| `mincut_16` | Stoer-Wagner mincut on 16 nodes | < 50 us | ~331 ns |
| `security_gate_p1` | Unified security gate (P1 tier) | -- | ~17 ns |

> **See also:** [Performance](11-performance.md) for full benchmark analysis and optimization guidance.

---

## Step 3: Build for Bare Metal

Cross-compile the kernel for AArch64:

```bash
make build
```

Under the hood this runs:

```bash
RUSTFLAGS="-C link-arg=-Trvm.ld" \
    cargo build --target aarch64-unknown-none --release -p rvm-kernel
```

The linker script `rvm.ld` places the kernel entry point at `0x4000_0000`, which is the address QEMU's `-kernel` flag expects for the `virt` machine.

The output is an ELF binary at:

```
target/aarch64-unknown-none/release/rvm-kernel
```

> **See also:** [Bare Metal](12-bare-metal.md) for details on the linker script, EL2 entry, and stage-2 page tables.

---

## Step 4: Boot in QEMU

Launch the kernel in QEMU:

```bash
make run
```

This starts QEMU with the following configuration:

| Parameter | Value | Why |
|-----------|-------|-----|
| Machine | `virt` | ARM virtual platform with GICv2, PL011, generic timer |
| CPU | `cortex-a72` | ARMv8-A with EL2 support |
| Memory | `128M` | Sufficient for development; Seed profile needs far less |
| Display | `-nographic` | All output goes to the terminal via PL011 UART |

You should see boot output on your terminal. The kernel executes a 7-phase boot sequence (ADR-137):

```
Phase 0: Reset vector
Phase 1: Hardware detect
Phase 2: MMU setup
Phase 3: Hypervisor mode (EL2)
Phase 4: Kernel object init
Phase 5: First witness (genesis attestation)
Phase 6: Scheduler entry
```

Each phase emits a witness record before advancing to the next.

**To exit QEMU:** press `Ctrl-A` then `X`.

> **See also:** [Bare Metal](12-bare-metal.md) for hardware details, [Core Concepts](02-core-concepts.md) for what the boot phases mean.

---

## Step 5: Explore the API

The easiest way to use RVM as a library is to depend on `rvm-kernel`, which re-exports every subsystem crate under a unified namespace:

```toml
# In your Cargo.toml
[dependencies]
rvm-kernel = { path = "crates/rvm-kernel" }
```

Then import the modules you need:

```rust
use rvm_kernel::{
    types,      // Foundation types: PartitionId, Capability, WitnessRecord, etc.
    cap,        // Capability manager, derivation trees, proof verifier
    witness,    // Witness log, emitter, hash chain, replay queries
    proof,      // Proof engine, P1/P2/P3 tiers, TEE pipeline, signers
    partition,  // Partition manager, lifecycle, IPC, split/merge
    sched,      // Scheduler, 2-signal priority, SMP coordinator
    memory,     // Buddy allocator, tier manager, reconstruction pipeline
    coherence,  // Coherence graph, mincut, scoring, pressure signals
    boot,       // 7-phase boot sequence, measured boot
    wasm,       // WebAssembly agent runtime (optional)
    security,   // Unified security gate, attestation, DMA budgets
};
```

Each module corresponds to one crate in the workspace. You can also depend on individual crates directly if you only need a subset:

```toml
[dependencies]
rvm-types   = { path = "crates/rvm-types" }
rvm-cap     = { path = "crates/rvm-cap" }
rvm-witness = { path = "crates/rvm-witness" }
```

> **See also:** [Crate Reference](04-crate-reference.md) for the full API surface of each crate.

---

## What's Next?

Now that you have a working build, choose where to go based on what you want to learn:

| Your Goal | Next Chapter |
|-----------|-------------|
| Understand the mental model behind RVM | [Core Concepts](02-core-concepts.md) |
| See how the crates fit together | [Architecture](03-architecture.md) |
| Write code against the API | [Crate Reference](04-crate-reference.md) |
| Deploy on real hardware | [Bare Metal](12-bare-metal.md) |
| Understand the benchmark numbers | [Performance](11-performance.md) |
| Run WASM agents | [WASM Agents](09-wasm-agents.md) |

---

## Cross-References

- [Core Concepts](02-core-concepts.md) -- what coherence domains, capabilities, and witnesses mean
- [Architecture](03-architecture.md) -- the four-layer stack and crate dependency graph
- [Bare Metal](12-bare-metal.md) -- AArch64 details, linker script, EL2, PL011 UART
- [Performance](11-performance.md) -- full benchmark analysis and tuning
- [Troubleshooting](14-troubleshooting.md) -- common build errors and QEMU issues
