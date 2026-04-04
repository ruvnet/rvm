//! Witness record re-exports from rvm-types.
//!
//! The canonical `WitnessRecord` and `ActionKind` definitions live in
//! `rvm-types` so they can be shared across all RVM crates. This module
//! re-exports them for convenience.

pub use rvm_types::ActionKind;
pub use rvm_types::WitnessRecord;
