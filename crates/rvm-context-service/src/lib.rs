//! Durable hosted implementation of the governed `ruv://` context contract.
//!
//! RVM remains the authorization and witness authority. This crate runs after
//! authorization and adds encrypted immutable storage, transactional alias
//! state, tenant-sharded RuVector retrieval, durable receipts, and purge
//! outboxes. It requires Rust 1.85 because the upstream REDB-backed RuVector
//! adapter has that MSRV; the `no_std` `rvm-context` contract remains on 1.77.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::module_name_repetitions)]

mod active_index;
mod compiler;
mod constellation;
mod crypto;
mod embed;
mod error;
mod gateway;
mod receipt_drainer;
mod receipt_store;
mod resolver;
mod store;

pub use compiler::{
    CompiledContextArtifact, ContextCompileRequest, DerivedContextView, RvfContextCompiler,
};
pub use constellation::{
    compile_discovery_manifest, CompiledDiscoveryManifest, MAX_DISCOVERY_MANIFEST_BYTES,
};
pub use crypto::{DataKeyProvider, LocalKeyProvider, WrappedDataKey};
pub use embed::{ContextEmbedder, HashEmbedder};
pub use error::{ServiceError, ServiceResult};
pub use gateway::{ContextGateway, GatewayResponse};
pub use receipt_drainer::ReceiptDrainer;
pub use receipt_store::{DurableReceiptStore, ReceiptCursor};
pub use resolver::{NoopPurgeSink, PersistentContextResolver, PurgeSink, ResolverOptions};
