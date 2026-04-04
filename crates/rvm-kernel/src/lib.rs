//! # RVM Kernel
//!
//! Top-level integration crate for the RVM (RuVix Virtual Machine)
//! coherence-native microhypervisor. This crate wires together all
//! subsystems (HAL, capabilities, witness, proof, partitions, scheduler,
//! memory, coherence, boot, Wasm, and security) into a single API
//! surface.
//!
//! ## Architecture
//!
//! ```text
//!          +---------------------------------------------+
//!          |                  rvm-kernel                  |
//!          |                                             |
//!          |  +----------+  +----------+  +-----------+  |
//!          |  | rvm-boot |  | rvm-sched|  |rvm-memory |  |
//!          |  +----+-----+  +----+-----+  +-----+-----+  |
//!          |       |             |              |         |
//!          |  +----+-------------+--------------+-----+  |
//!          |  |            rvm-partition               |  |
//!          |  +----+--------+----------+---------+----+  |
//!          |       |        |          |         |       |
//!          |  +----+--+ +---+----+ +---+---+ +---+----+  |
//!          |  |rvm-cap| |rvm-wit.| |rvm-prf| |rvm-sec.|  |
//!          |  +----+--+ +---+----+ +---+---+ +---+----+  |
//!          |       |        |          |         |       |
//!          |  +----+--------+----------+---------+----+  |
//!          |  |              rvm-types                |   |
//!          |  +----+----------------------------------+  |
//!          |       |                                     |
//!          |  +----+--+  +----------+                    |
//!          |  |rvm-hal|  |rvm-wasm  | (optional)         |
//!          |  +-------+  +----------+                    |
//!          +---------------------------------------------+
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Re-export all subsystem crates for unified access.
pub use rvm_boot as boot;
/// Capability-based access control.
pub use rvm_cap as cap;
/// Coherence monitoring and Phi computation.
pub use rvm_coherence as coherence;
/// Hardware abstraction layer traits.
pub use rvm_hal as hal;
/// Guest memory management.
pub use rvm_memory as memory;
/// Partition lifecycle management.
pub use rvm_partition as partition;
/// Proof-gated state transitions.
pub use rvm_proof as proof;
/// Coherence-weighted scheduler.
pub use rvm_sched as sched;
/// Security policy enforcement.
pub use rvm_security as security;
/// Core type definitions.
pub use rvm_types as types;
/// WebAssembly guest runtime.
pub use rvm_wasm as wasm;
/// Witness trail management.
pub use rvm_witness as witness;

/// RVM version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// RVM crate count (number of subsystem crates).
pub const CRATE_COUNT: usize = 13;
