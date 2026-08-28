//! Hosted RVM governance for stock iOS applications.
//!
//! `HostedIOS` is an application-level boundary beneath iOS, never a claim of
//! stage-2 translation, IOMMU control, GPU partitioning, measured boot, exact
//! Neural Engine placement, hard real-time execution, or background liveness.
//! The host app remains trusted computing base and must route native sensor,
//! network, model, and Metal operations through this crate for its receipts to
//! describe the whole application.
//!
//! The boundary has four concrete parts:
//! - exact policy bytes must match trusted, signed RVF metadata;
//! - every fine-grained scope must also match the RVF's broad capability set;
//! - current iOS authorization/support and operator budgets are intersected at
//!   each operation;
//! - a full-content HMAC chain records intent before native dispatch and the
//!   completion, failure, or denial after it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions, clippy::doc_markdown)]

mod platform;
mod policy;
mod receipt;
mod runtime;
mod wasm_bridge;

pub use platform::{HostedIosNonGuarantees, HostedIosProfile, IosAuthorization, IosPlatformFacts};
pub use policy::{IosPolicy, IosPolicyError, IosScope, IOS_CAPABILITY_KEY, IOS_POLICY_VERSION_KEY};
pub use receipt::{
    verify_agent_execution_seal, verify_receipt_chain, verify_sealed_receipt_chain,
    AgentExecutionLimits, AgentExecutionOutcome, AgentExecutionSeal, IosReceipt, ReceiptChain,
    ReceiptEvent, ReceiptIntegrityError, ReceiptSeal, ReceiptSessionIdentity,
};
pub use runtime::{
    DispatchError, DispatchFailure, GovernedIosRuntime, IosArtifactOrigin, IosBudget,
    IosOperationRequest, IosOperatorPolicy, IosReason, IOS_GUEST_DENIED, IOS_GUEST_INVALID_SCOPE,
    IOS_NATIVE_DEADLINE_EXCEEDED, MAX_IOS_CALLS_PER_SCOPE, MAX_IOS_DURATION_MS,
    MAX_IOS_UNITS_PER_CALL,
};
pub use wasm_bridge::{
    execute_verified_ios_agent, IosAgentError, IosAgentExecution, IosNativeBridge, IosWasmHandler,
};

/// HostedIOS contract version recorded in policy and architecture evidence.
pub const HOSTED_IOS_CONTRACT_VERSION: u32 = 1;
