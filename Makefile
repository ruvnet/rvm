# RVM Build System for AArch64 QEMU virt
#
# Prerequisites:
#   rustup target add aarch64-unknown-none
#   cargo install cargo-binutils
#   rustup component add llvm-tools
#   brew install qemu  (or equivalent)
#
# Usage:
#   make build    - Build the kernel for AArch64
#   make check    - Type-check without building (fast)
#   make run      - Build and run in QEMU
#   make test     - Run host tests (all crates)
#   make clean    - Remove build artifacts

TARGET = aarch64-unknown-none
KERNEL_CRATE = rvm-kernel
KERNEL_ELF = target/$(TARGET)/release/$(KERNEL_CRATE)
KERNEL_BIN = target/$(TARGET)/release/rvm-kernel.bin

# QEMU settings
QEMU = qemu-system-aarch64
QEMU_MACHINE = virt
QEMU_CPU = cortex-a72
QEMU_MEM = 128M

# Cargo flags
CARGO_FLAGS = --target $(TARGET) --release
LINKER_SCRIPT = rvm.ld

.PHONY: build check run test clean objdump

# Type-check the HAL crate for AArch64 (fast verification).
check:
	cargo check --target $(TARGET) -p rvm-hal

# Build the full kernel binary for AArch64.
build:
	RUSTFLAGS="-C link-arg=-T$(LINKER_SCRIPT)" \
		cargo build $(CARGO_FLAGS) -p $(KERNEL_CRATE)

# Convert ELF to raw binary for QEMU -kernel.
bin: build
	rust-objcopy --strip-all -O binary $(KERNEL_ELF) $(KERNEL_BIN)

# Run in QEMU (press Ctrl-A X to exit).
run: build
	$(QEMU) \
		-M $(QEMU_MACHINE) \
		-cpu $(QEMU_CPU) \
		-m $(QEMU_MEM) \
		-nographic \
		-kernel $(KERNEL_ELF)

# Run host tests for all workspace crates.
test:
	cargo test --workspace

# Disassemble the kernel binary.
objdump: build
	rust-objdump -d $(KERNEL_ELF) | head -200

# Remove build artifacts.
clean:
	cargo clean
