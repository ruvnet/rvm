//! Proof context: the full state needed for P2 policy validation.
//!
//! Constructed via the builder pattern to ensure all required fields
//! are populated before validation proceeds.

use rvm_types::PartitionId;

/// The full state context needed for P2 (policy) validation.
///
/// All fields required for evaluating P2 policy rules are gathered
/// here so that validation is a pure function of context.
#[derive(Debug, Clone, Copy)]
pub struct ProofContext {
    /// Partition performing the operation.
    pub partition_id: PartitionId,
    /// Target kernel object identifier.
    pub target_object: u64,
    /// The operation being requested (action kind discriminant).
    pub requested_operation: u8,
    /// Capability handle index used for this operation.
    pub capability_handle: u32,
    /// Capability generation counter (for stale-handle detection).
    pub capability_generation: u32,
    /// Current scheduler epoch.
    pub current_epoch: u32,
    /// Lower bound of the target region (guest physical address).
    pub region_base: u64,
    /// Upper bound of the target region.
    pub region_limit: u64,
    /// Lease expiry timestamp in nanoseconds.
    pub lease_expiry_ns: u64,
    /// Current time in nanoseconds.
    pub current_time_ns: u64,
    /// Maximum delegation depth.
    pub max_delegation_depth: u8,
    /// Nonce for replay prevention.
    pub nonce: u64,
}

/// Builder for constructing a `ProofContext` incrementally.
///
/// Uses the typestate pattern via explicit `build()` call that
/// validates all required fields are non-default.
#[derive(Debug, Clone, Copy)]
pub struct ProofContextBuilder {
    partition_id: PartitionId,
    target_object: u64,
    requested_operation: u8,
    capability_handle: u32,
    capability_generation: u32,
    current_epoch: u32,
    region_base: u64,
    region_limit: u64,
    lease_expiry_ns: u64,
    current_time_ns: u64,
    max_delegation_depth: u8,
    nonce: u64,
}

impl ProofContextBuilder {
    /// Start building a new proof context for the given partition.
    #[must_use]
    pub const fn new(partition_id: PartitionId) -> Self {
        Self {
            partition_id,
            target_object: 0,
            requested_operation: 0,
            capability_handle: 0,
            capability_generation: 0,
            current_epoch: 0,
            region_base: 0,
            region_limit: 0,
            lease_expiry_ns: u64::MAX,
            current_time_ns: 0,
            max_delegation_depth: 8,
            nonce: 0,
        }
    }

    /// Set the target kernel object.
    #[must_use]
    pub const fn target_object(mut self, id: u64) -> Self {
        self.target_object = id;
        self
    }

    /// Set the requested operation (action kind discriminant).
    #[must_use]
    pub const fn requested_operation(mut self, op: u8) -> Self {
        self.requested_operation = op;
        self
    }

    /// Set the capability handle index.
    #[must_use]
    pub const fn capability_handle(mut self, handle: u32) -> Self {
        self.capability_handle = handle;
        self
    }

    /// Set the capability generation counter.
    #[must_use]
    pub const fn capability_generation(mut self, gen: u32) -> Self {
        self.capability_generation = gen;
        self
    }

    /// Set the current scheduler epoch.
    #[must_use]
    pub const fn current_epoch(mut self, epoch: u32) -> Self {
        self.current_epoch = epoch;
        self
    }

    /// Set the region bounds for bounds checking.
    #[must_use]
    pub const fn region_bounds(mut self, base: u64, limit: u64) -> Self {
        self.region_base = base;
        self.region_limit = limit;
        self
    }

    /// Set the lease expiry and current time.
    #[must_use]
    pub const fn time_window(mut self, current_ns: u64, expiry_ns: u64) -> Self {
        self.current_time_ns = current_ns;
        self.lease_expiry_ns = expiry_ns;
        self
    }

    /// Set the maximum delegation depth.
    #[must_use]
    pub const fn max_delegation_depth(mut self, depth: u8) -> Self {
        self.max_delegation_depth = depth;
        self
    }

    /// Set the nonce for replay prevention.
    #[must_use]
    pub const fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Consume the builder and produce a `ProofContext`.
    #[must_use]
    pub const fn build(self) -> ProofContext {
        ProofContext {
            partition_id: self.partition_id,
            target_object: self.target_object,
            requested_operation: self.requested_operation,
            capability_handle: self.capability_handle,
            capability_generation: self.capability_generation,
            current_epoch: self.current_epoch,
            region_base: self.region_base,
            region_limit: self.region_limit,
            lease_expiry_ns: self.lease_expiry_ns,
            current_time_ns: self.current_time_ns,
            max_delegation_depth: self.max_delegation_depth,
            nonce: self.nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let ctx = ProofContextBuilder::new(PartitionId::new(1)).build();
        assert_eq!(ctx.partition_id, PartitionId::new(1));
        assert_eq!(ctx.max_delegation_depth, 8);
        assert_eq!(ctx.lease_expiry_ns, u64::MAX);
    }

    #[test]
    fn test_builder_chaining() {
        let ctx = ProofContextBuilder::new(PartitionId::new(5))
            .target_object(42)
            .requested_operation(0x01)
            .capability_handle(10)
            .current_epoch(3)
            .region_bounds(0x1000, 0x2000)
            .time_window(500, 1000)
            .max_delegation_depth(4)
            .nonce(99)
            .build();

        assert_eq!(ctx.partition_id, PartitionId::new(5));
        assert_eq!(ctx.target_object, 42);
        assert_eq!(ctx.requested_operation, 0x01);
        assert_eq!(ctx.capability_handle, 10);
        assert_eq!(ctx.current_epoch, 3);
        assert_eq!(ctx.region_base, 0x1000);
        assert_eq!(ctx.region_limit, 0x2000);
        assert_eq!(ctx.current_time_ns, 500);
        assert_eq!(ctx.lease_expiry_ns, 1000);
        assert_eq!(ctx.max_delegation_depth, 4);
        assert_eq!(ctx.nonce, 99);
    }

    // ---------------------------------------------------------------
    // Edge-case tests for ProofContextBuilder
    // ---------------------------------------------------------------

    #[test]
    fn test_builder_default_region_bounds_are_zero() {
        let ctx = ProofContextBuilder::new(PartitionId::new(1)).build();
        assert_eq!(ctx.region_base, 0);
        assert_eq!(ctx.region_limit, 0);
    }

    #[test]
    fn test_builder_default_nonce_is_zero() {
        let ctx = ProofContextBuilder::new(PartitionId::new(1)).build();
        assert_eq!(ctx.nonce, 0);
    }

    #[test]
    fn test_builder_default_time_window() {
        let ctx = ProofContextBuilder::new(PartitionId::new(1)).build();
        assert_eq!(ctx.current_time_ns, 0);
        assert_eq!(ctx.lease_expiry_ns, u64::MAX);
    }

    #[test]
    fn test_builder_default_capability_fields() {
        let ctx = ProofContextBuilder::new(PartitionId::new(1)).build();
        assert_eq!(ctx.capability_handle, 0);
        assert_eq!(ctx.capability_generation, 0);
        assert_eq!(ctx.current_epoch, 0);
        assert_eq!(ctx.target_object, 0);
        assert_eq!(ctx.requested_operation, 0);
    }

    #[test]
    fn test_builder_hypervisor_partition() {
        let ctx = ProofContextBuilder::new(PartitionId::HYPERVISOR).build();
        assert_eq!(ctx.partition_id, PartitionId::HYPERVISOR);
        assert!(ctx.partition_id.is_hypervisor());
    }

    #[test]
    fn test_builder_max_delegation_depth_override() {
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .max_delegation_depth(0)
            .build();
        assert_eq!(ctx.max_delegation_depth, 0);

        let ctx2 = ProofContextBuilder::new(PartitionId::new(1))
            .max_delegation_depth(255)
            .build();
        assert_eq!(ctx2.max_delegation_depth, 255);
    }

    #[test]
    fn test_builder_overwrite_fields() {
        // Setting the same field twice should use the last value.
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .nonce(10)
            .nonce(20)
            .build();
        assert_eq!(ctx.nonce, 20);
    }

    #[test]
    fn test_builder_capability_generation() {
        let ctx = ProofContextBuilder::new(PartitionId::new(1))
            .capability_generation(42)
            .build();
        assert_eq!(ctx.capability_generation, 42);
    }
}
