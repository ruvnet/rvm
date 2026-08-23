//! Raises the wasm stack for this module.
//!
//! The governed runtime holds its capability table, grant table, and witness
//! ring inline: `ContextAuthority` alone is roughly 68 KiB regardless of slot
//! count, because its proof verifier dominates, and the witness ring adds
//! another 64 KiB. Constructing that on wasm32 walks through several stack
//! temporaries in an unoptimized build and exhausts the 1 MiB default stack,
//! which surfaces as an opaque "memory access out of bounds" rather than a
//! clean overflow.
//!
//! Shrinking the slot counts does not fix it (16 slots still costs ~66 KiB),
//! so the module asks for a larger stack instead. This travels with the crate,
//! so a plain `cargo build` and `wasm-pack` both get it without a global
//! `.cargo/config.toml`.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        const STACK_SIZE: &str = "-zstack-size=4194304";
        println!("cargo::rustc-link-arg={STACK_SIZE}");
        println!("cargo::rustc-link-arg-tests={STACK_SIZE}");
    }
}
