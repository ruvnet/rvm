//! Governed cognitive context for RVM through canonical `ruv://` names.
//!
//! This crate names context but never treats a name as authority. Every
//! resolver operation first passes through an RVM capability binding, and
//! every decision is committed to the witness trail. Immutable revisions are
//! whole RVF SHA-256 identities; versionless names are mutable aliases changed
//! only with compare-and-swap.
//!
//! The public surface separates inspection, reading, mutation, and execution.
//! In particular, resolving or reading a skill never confers permission to
//! execute it.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod capability;
pub mod error;
pub mod flow;
pub mod profile;
pub mod receipt;
pub mod resolver;
pub mod runtime;
pub mod uri;

pub use capability::{
    AuthorizedRequest, CapabilityHandle, ContextAuthority, ContextGrant, ContextGrantTable,
    ContextOperation, ContextRequest, ContextScope, ContextViewMask, MAX_SEARCH_RESULTS,
};
pub use error::{ContextError, ContextResult};
pub use flow::{
    EgressBudget, EgressDecision, EgressReceipt, FlowClasses, FlowError, FlowLabel, FlowResult,
    MAX_FLOW_PARENTS, MAX_FLOW_TAG_BYTES,
};
pub use profile::{
    ContextProfile, ContextProfileError, DerivedView, ProfileTrust, ProfileView,
    VerifiedContextProfile, CONTEXT_PROFILE_MAGIC, CONTEXT_PROFILE_VERSION, MAX_CONTEXT_RVF_BYTES,
};
pub use receipt::{
    rvf_witness_entry_hash, ContextEpochReceipt, ContextReceiptError, SignedContextEpochReceipt,
    VerifiedContextEpochReceipt, CONTEXT_RECEIPT_ENCODED_SIZE, CONTEXT_RECEIPT_VERSION,
    MAX_CONTEXT_EPOCH_RECORDS, RVF_WITNESS_COMPUTATION, RVF_WITNESS_ENTRY_SIZE,
};
pub use resolver::{
    AliasGeneration, AliasSnapshot, ContextHit, ContextResolver, MemoryResolver, ResolvedContext,
    MAX_ENUM_RESULTS, MAX_RVF_BYTES, MAX_SEARCH_QUERY_BYTES,
};
pub use runtime::{
    ContextClock, ContextRuntime, ExecutionPermit, LogicalContextClock, ReceiptChainState,
};
pub use uri::{
    Authority, Collection, PathSegment, PinnedRuvUri, ProgressiveView, Revision, RuvUri,
    RuvUriBuilder, Subject, SubjectId, SubjectKind, TenantId, UriError,
};

/// Version of the RVM `ruv://` namespace contract.
pub const RUV_CONTEXT_CONTRACT_VERSION: u32 = 1;
