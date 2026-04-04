//! Witness emitter: convenience helpers for constructing witness records.

use crate::log::WitnessLog;
use rvm_types::{ActionKind, WitnessRecord};

/// Helper for emitting witness records with domain-specific parameters.
pub struct WitnessEmitter<'a, const N: usize> {
    log: &'a WitnessLog<N>,
}

impl<'a, const N: usize> WitnessEmitter<'a, N> {
    /// Creates a new emitter backed by the given log.
    #[must_use]
    pub const fn new(log: &'a WitnessLog<N>) -> Self {
        Self { log }
    }

    /// Emits a partition creation witness.
    #[must_use]
    pub fn emit_partition_create(
        &self, actor: u32, new_partition_id: u64, cap_hash: u32, ts: u64,
    ) -> u64 {
        let mut r = WitnessRecord::zeroed();
        r.action_kind = ActionKind::PartitionCreate as u8;
        r.proof_tier = 1;
        r.actor_partition_id = actor;
        r.target_object_id = new_partition_id;
        r.capability_hash = cap_hash;
        r.timestamp_ns = ts;
        self.log.append(r)
    }

    /// Emits a partition destroy witness.
    #[must_use]
    pub fn emit_partition_destroy(
        &self, actor: u32, partition_id: u64, cap_hash: u32, ts: u64,
    ) -> u64 {
        let mut r = WitnessRecord::zeroed();
        r.action_kind = ActionKind::PartitionDestroy as u8;
        r.proof_tier = 1;
        r.actor_partition_id = actor;
        r.target_object_id = partition_id;
        r.capability_hash = cap_hash;
        r.timestamp_ns = ts;
        self.log.append(r)
    }

    /// Emits a capability grant witness.
    #[must_use]
    pub fn emit_capability_grant(
        &self, actor: u32, target: u64, cap_hash: u32, payload: [u8; 8], ts: u64,
    ) -> u64 {
        let mut r = WitnessRecord::zeroed();
        r.action_kind = ActionKind::CapabilityGrant as u8;
        r.proof_tier = 1;
        r.actor_partition_id = actor;
        r.target_object_id = target;
        r.capability_hash = cap_hash;
        r.payload = payload;
        r.timestamp_ns = ts;
        self.log.append(r)
    }

    /// Emits a capability revoke witness.
    #[must_use]
    pub fn emit_capability_revoke(
        &self, actor: u32, target: u64, cap_hash: u32, ts: u64,
    ) -> u64 {
        let mut r = WitnessRecord::zeroed();
        r.action_kind = ActionKind::CapabilityRevoke as u8;
        r.proof_tier = 1;
        r.actor_partition_id = actor;
        r.target_object_id = target;
        r.capability_hash = cap_hash;
        r.timestamp_ns = ts;
        self.log.append(r)
    }

    /// Emits a memory region map witness.
    #[must_use]
    pub fn emit_memory_map(
        &self, actor: u32, region_id: u64, cap_hash: u32, payload: [u8; 8], ts: u64,
    ) -> u64 {
        let mut r = WitnessRecord::zeroed();
        r.action_kind = ActionKind::RegionMap as u8;
        r.proof_tier = 2;
        r.actor_partition_id = actor;
        r.target_object_id = region_id;
        r.capability_hash = cap_hash;
        r.payload = payload;
        r.timestamp_ns = ts;
        self.log.append(r)
    }

    /// Emits a proof rejection witness.
    #[must_use]
    pub fn emit_proof_rejected(
        &self, actor: u32, target: u64, cap_hash: u32, ts: u64,
    ) -> u64 {
        let mut r = WitnessRecord::zeroed();
        r.action_kind = ActionKind::ProofRejected as u8;
        r.actor_partition_id = actor;
        r.target_object_id = target;
        r.capability_hash = cap_hash;
        r.timestamp_ns = ts;
        self.log.append(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_partition_create() {
        let log = WitnessLog::<16>::new();
        let emitter = WitnessEmitter::new(&log);
        let seq = emitter.emit_partition_create(1, 10, 0xABCD, 1000);
        assert_eq!(seq, 0);

        let record = log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::PartitionCreate as u8);
        assert_eq!(record.actor_partition_id, 1);
        assert_eq!(record.target_object_id, 10);
        assert_eq!(record.capability_hash, 0xABCD);
    }

    #[test]
    fn test_emit_multiple() {
        let log = WitnessLog::<16>::new();
        let emitter = WitnessEmitter::new(&log);
        emitter.emit_partition_create(1, 10, 0, 100);
        emitter.emit_capability_grant(1, 2, 0, [0; 8], 200);
        emitter.emit_memory_map(1, 50, 0, [0; 8], 300);
        assert_eq!(log.total_emitted(), 3);
    }
}
