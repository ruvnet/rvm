# Bare-Metal Deployment: Running on Real Hardware

RVM is not a library that runs inside an operating system. It *is* the
operating system -- a microhypervisor that boots from a reset vector, sets up
page tables, and takes control of the hardware. This chapter explains how to
build the bare-metal kernel image, run it on QEMU, understand the boot
sequence, and prepare for deployment on physical hardware.

For the architecture of the crates that compose the kernel, see
[Architecture](03-architecture.md). For the seven-phase boot sequence from
the software perspective, see the `rvm-boot` entry in [Crate
Reference](04-crate-reference.md).

---

## 1. Prerequisites

You need the following tools installed before building a bare-metal kernel.

**Rust 1.77 or later:**

```bash
rustup update stable
rustc --version  # 1.77.0+
```

**AArch64 bare-metal target:**

```bash
rustup target add aarch64-unknown-none
```

This installs the `core` library cross-compiled for AArch64 with no OS. RVM
does not link against `std` or any C runtime.

**cargo-binutils (for ELF-to-binary conversion):**

```bash
cargo install cargo-binutils
rustup component add llvm-tools
```

This provides `rust-objcopy` (for converting ELF to raw binary) and
`rust-objdump` (for disassembly).

**QEMU (for emulated boot):**

```bash
# macOS
brew install qemu

# Ubuntu / Debian
sudo apt install qemu-system-aarch64

# Verify
qemu-system-aarch64 --version
```

QEMU 8.0 or later is recommended. The `virt` machine type that RVM targets
is well-tested across QEMU versions.

---

## 2. The Linker Script (`rvm.ld`)

The file `rvm.ld` at the workspace root controls the memory layout of the
kernel image. It tells the linker where to place each section in physical
memory.

### Entry point

```text
ENTRY(_start)
```

The symbol `_start` is defined in `rvm-hal`'s AArch64 assembly boot stub. It
is the first instruction the CPU executes after reset.

### Memory map

```text
MEMORY {
    RAM (rwx) : ORIGIN = 0x40000000, LENGTH = 128M
}
```

QEMU's `virt` machine places RAM at physical address `0x4000_0000`. The
linker script tells Rust to place all code and data within this 128 MB region.
On physical hardware, adjust the origin and length to match your board's
memory map.

### Section layout

| Section | Alignment | Contents |
|---|---|---|
| `.text.boot` | Load address (0x4000_0000) | Assembly boot stub: EL2 check, stack setup, BSS clear |
| `.text` | 4 bytes | All Rust code |
| `.rodata` | 8 bytes | Read-only data (string literals, const tables) |
| `.data` | 8 bytes | Initialized mutable data |
| `.bss` | 16 bytes | Zero-initialized mutable data |
| Stack | 4 KB page | 64 KB hypervisor stack, growing downward |
| Page tables | 4 KB page | L1 + 4 L2 page tables (5 x 4 KB = 20 KB) |
| Heap | 4 KB page | Optional, reserved for future use |

### Exported symbols

The linker script exports symbols that the boot code uses:

| Symbol | Purpose |
|---|---|
| `_start` | Entry point (in `.text.boot`) |
| `__bss_start` | Start of BSS (zeroed during boot) |
| `__bss_end` | End of BSS |
| `__stack_top` | Initial stack pointer |
| `__page_tables` | Start of page table region |
| `__heap_start` | Start of optional heap region |

---

## 3. Build Steps

The `Makefile` in the workspace root provides the standard build targets.

### Type-check (fast verification)

```bash
make check
```

This runs `cargo check --target aarch64-unknown-none -p rvm-hal`. It
verifies that the HAL crate compiles for the bare-metal target without
producing a binary. Use this during development for fast feedback.

### Build the kernel ELF

```bash
make build
```

This runs:

```bash
RUSTFLAGS="-C link-arg=-Trvm.ld" cargo build --target aarch64-unknown-none --release -p rvm-kernel
```

The output is an ELF binary at
`target/aarch64-unknown-none/release/rvm-kernel`. The release profile applies
opt-level 3, fat LTO, single codegen unit, symbol stripping, and
`panic=abort`. See [Performance](11-performance.md) for details on the
release profile.

### Convert to raw binary

```bash
make bin
```

This strips the ELF headers and produces a flat binary at
`target/aarch64-unknown-none/release/rvm-kernel.bin`. Use this format when
your bootloader expects a raw image rather than ELF.

### Disassemble

```bash
make objdump
```

This runs `rust-objdump -d` on the kernel ELF and prints the first 200 lines
of disassembly. Useful for verifying that `_start` is at the expected load
address and inspecting generated code quality.

---

## 4. QEMU Boot

```bash
make run
```

This executes:

```bash
qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a72 \
    -m 128M \
    -nographic \
    -kernel target/aarch64-unknown-none/release/rvm-kernel
```

### QEMU parameters explained

| Flag | Value | Purpose |
|---|---|---|
| `-M` | `virt` | ARM virtual platform -- PL011 UART, GICv2, generic timer |
| `-cpu` | `cortex-a72` | ARMv8-A CPU with EL2 support |
| `-m` | `128M` | 128 MB of RAM starting at 0x4000_0000 |
| `-nographic` | -- | UART output goes to the terminal (no GUI window) |
| `-kernel` | ELF path | QEMU loads the ELF and jumps to its entry point |

Press **Ctrl-A X** to exit QEMU.

### What you should see

On a successful boot, the kernel prints a banner and phase completions to the
PL011 UART:

```text
[RVM] Boot phase 0: HAL init ... OK
[RVM] Boot phase 1: Memory init ... OK
[RVM] Boot phase 2: Capability init ... OK
[RVM] Boot phase 3: Witness init ... OK
[RVM] Boot phase 4: Scheduler init ... OK
[RVM] Boot phase 5: Root partition ... OK
[RVM] Boot phase 6: Handoff ... OK
[RVM] Kernel ready. 7/7 phases complete.
```

If QEMU hangs at startup, see [Troubleshooting](14-troubleshooting.md).

---

## 5. The Boot Sequence

RVM follows a 7-phase deterministic boot sequence defined in ADR-137. Each
phase is gated: the next phase cannot begin until the current one completes
successfully and emits a witness record.

```text
Phase 0: HAL init         -- timer, MMU stubs, interrupt controller
Phase 1: Memory init      -- physical page allocator (BuddyAllocator)
Phase 2: Capability init  -- capability table with root capabilities
Phase 3: Witness init     -- witness log ring buffer, genesis record
Phase 4: Scheduler init   -- per-CPU run queues, epoch tracker
Phase 5: Root partition   -- create partition 0 with full rights
Phase 6: Handoff          -- transfer control to the root partition
```

### Phase flow

The `BootSequence` struct in `rvm-boot` tracks which phases have completed.
It enforces ordering: calling `complete_stage()` for phase N when phase N-1
has not completed returns an error.

Each phase extends the measured boot hash chain (see section 6 below). The
`BootContext` struct holds all transient state needed during boot:

```rust
pub struct BootContext {
    pub sequence: BootSequence,    // Phase tracker
    pub measured: MeasuredBootState, // Hash chain
    pub dtb_ptr: u64,             // Device tree blob pointer
    pub ram_size: u64,            // Detected RAM
    pub uart_ready: bool,         // UART available for output
}
```

### Phase 0: HAL init

The platform HAL initializes:
- PL011 UART for debug output
- ARM generic timer for monotonic time
- GICv2 interrupt controller
- Stage-2 MMU stubs (identity mapping for early boot)

### Phase 5: Root partition

The root partition (partition 0) is created with full capability rights
(`READ | WRITE | EXECUTE | GRANT | REVOKE | PROVE`). It owns all physical
memory and all device leases. Subsequent partitions are created by the root
partition delegating subsets of its authority.

### Phase 6: Handoff

The scheduler begins its main loop. Control passes to the root partition's
first vCPU. From this point forward, RVM is fully operational.

For the full API of each boot phase, see the `rvm-boot` section of [Crate
Reference](04-crate-reference.md).

---

## 6. Measured Boot

The `MeasuredBootState` struct accumulates a cryptographic hash chain during
boot for remote attestation.

Before each phase executes, its code hash is extended into a running
accumulator:

```text
accumulator[n+1] = SHA-256(accumulator[n] || phase_index || phase_hash)
```

When the `crypto-sha256` feature is disabled (for minimal builds), the
fallback uses four overlapping FNV-1a windows to fill the 32-byte
accumulator.

The final attestation digest proves that exactly these code paths executed in
exactly this order. A remote verifier can compare the digest against a
known-good reference to detect tampering.

Key properties:

- **Deterministic.** The same code always produces the same digest.
- **Order-sensitive.** Swapping two phases produces a different digest.
- **Tamper-evident.** Changing any input byte changes the final digest.
- **Per-phase audit.** Individual phase hashes are recorded for replay.

```rust
let state = MeasuredBootState::new();
state.extend_measurement(BootStage::ResetVector, &phase_0_hash);
// ... extend for each phase ...
let digest = state.get_attestation_digest(); // [u8; 32]
```

See [Security](10-security.md) for how measured boot integrates with the
TEE attestation pipeline.

---

## 7. Hardware Profile: Seed

The Seed profile targets microcontroller-class hardware with 64 KB to 1 MB
of RAM. At this scale, RVM provides:

- Capability-enforced partition isolation
- Witness trail (reduced ring buffer, e.g., 64 records = 4 KB)
- Proof-gated mutations (P1 and P2 tiers)
- Deterministic boot with measured attestation

What Seed omits:

- Coherence engine (no graph computation at this scale)
- WASM runtime (insufficient memory)
- Dormant/cold memory tiers (only hot and warm)
- MinCut and adaptive recomputation

To build for Seed, disable the `ruvector`, `alloc`, and `std` features and
set a small ring buffer capacity. The kernel footprint can be as small as a
few kilobytes of code plus the witness ring.

This is unique: no other hypervisor provides capability + proof + witness
security on devices that typically run bare C with no isolation at all. See
[Advanced and Exotic](13-advanced-exotic.md) for a deeper discussion.

---

## 8. Hardware Profile: Appliance

The Appliance profile targets systems with 1 to 32 GB of RAM. At this scale,
RVM enables the full feature set:

- Full coherence engine with MinCut and adaptive recomputation
- Four-tier memory model (hot, warm, dormant, cold)
- WASM agent runtime with per-epoch resource quotas
- Live partition split and merge
- RuVector integration for spectral graph analysis

This profile is intended for edge computing appliances, automotive ECUs,
industrial gateways, and multi-agent orchestration platforms.

---

## 9. Cargo Config

The file `.cargo/config.toml` provides default flags for bare-metal builds:

```toml
[target.aarch64-unknown-none]
rustflags = ["-C", "link-arg=-Trvm.ld"]
```

This tells Cargo to pass the linker script automatically whenever building
for `aarch64-unknown-none`. You do not need to set `RUSTFLAGS` manually
unless you are overriding the linker script path.

For host-target builds (`cargo test`, `cargo bench`), this config has no
effect. The linker script is only used when building for the bare-metal
target.

---

## 10. CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs four checks on
every push and pull request:

| Step | Command | Purpose |
|---|---|---|
| Host check | `cargo check` | Verify all crates compile on the host |
| Host tests | `cargo test` | Run the full 648-test suite |
| Clippy | `cargo clippy -- -D warnings` | Lint enforcement (zero warnings) |
| Cross-compile | `cargo check --target aarch64-unknown-none -p rvm-hal --no-default-features` | Verify the HAL compiles for bare metal |

The cross-compile step does not *run* the kernel (QEMU is not available in
CI). It only verifies that the code compiles for the bare-metal target. To
run the kernel, use `make run` on a machine with QEMU installed.

---

## Further Reading

- [Quick Start](01-quickstart.md) -- five-minute build and boot guide
- [Architecture](03-architecture.md) -- crate dependency tree and layer responsibilities
- [Performance](11-performance.md) -- benchmark suite and build profile details
- [Security](10-security.md) -- TEE integration and measured boot attestation
- [Advanced and Exotic](13-advanced-exotic.md) -- Seed and Appliance profiles in depth
- [Troubleshooting](14-troubleshooting.md) -- what to do when QEMU does not boot
- [Cross-Reference Index](cross-reference.md) -- find every mention of a concept
