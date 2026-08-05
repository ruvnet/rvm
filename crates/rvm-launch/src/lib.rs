//! The launch surface: state, checkpoints, and the witness records they emit.
//!
//! `rvm-host` decides *where* an agent can run. This crate covers what happens
//! to its state across that lifetime — suspend, checkpoint, resume, and the
//! lineage rules that decide when restoring is refused.
//!
//! ## The rule worth stating twice
//!
//! Every delta and every checkpoint carries the base RVF identity it belongs
//! to (ADR-288 §4). On open, the runtime compares that against the base it
//! actually loaded, and a mismatch is a lineage rejection: the state is
//! refused, execution does not begin with partial state, and the rejection
//! goes into the witness chain rather than being handled quietly.
//!
//! Instance identity is recorded as provenance but is deliberately *not* a
//! gate — ADR-289 acceptance criterion 7 requires suspending under one host
//! adapter and resuming under another, so the instance on the far side is a
//! new one by construction.
//!
//! ## Allocation
//!
//! `no_std` with `alloc` required: a delta chain and a witness log are both
//! variable-length. The decision path itself allocates nothing beyond those.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::doc_markdown)]

extern crate alloc;

pub mod checkpoint;
pub mod error;
pub mod state;
pub mod witness;
