//! Unified security gate — the single entry point for all privileged
//! operations in the RVM microhypervisor.
//!
//! No mutation occurs without passing through this gate. The pipeline:
//!
//! 1. **P1 capability check** -- Does the caller hold the required rights?
//! 2. **P2 policy validate** -- Is the policy satisfied?
//! 3. **Emit witness** -- Record the decision for audit.
//! 4. **Execute** -- Perform the operation.
//!
//! If any step fails, a `PROOF_REJECTED` witness is emitted and the
//! operation is denied.

use rvm_types::{ActionKind, CapRights, CapToken, CapType, RvmError, WitnessHash, WitnessRecord};
use rvm_witness::WitnessLog;

/// A request to the security gate.
#[derive(Debug, Clone, Copy)]
pub struct GateRequest {
    /// The capability token presented by the caller.
    pub token: CapToken,
    /// The required capability type.
    pub required_type: CapType,
    /// The required access rights.
    pub required_rights: CapRights,
    /// Optional proof commitment (required for state-mutating operations).
    pub proof_commitment: Option<WitnessHash>,
    /// The action being performed (for witness logging).
    pub action: ActionKind,
    /// Target object identifier.
    pub target_object_id: u64,
    /// Timestamp for the witness record.
    pub timestamp_ns: u64,
}

/// A successful gate response.
#[derive(Debug, Clone, Copy)]
pub struct GateResponse {
    /// The witness sequence number for this operation.
    pub witness_sequence: u64,
    /// The proof tier that was satisfied.
    pub proof_tier: u8,
}

/// Security errors specific to the gate pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    /// P1 capability check failed: wrong capability type.
    CapabilityTypeMismatch,
    /// P1 capability check failed: insufficient rights.
    InsufficientRights,
    /// P2 policy validation failed: proof commitment missing or invalid.
    PolicyViolation,
    /// An internal error occurred.
    Internal(RvmError),
}

/// The unified security gate.
///
/// Wraps the capability check, policy validation, and witness logging
/// into a single pipeline. The const generic `N` is the witness ring
/// buffer capacity.
pub struct SecurityGate<'a, const N: usize> {
    witness_log: &'a WitnessLog<N>,
}

impl<'a, const N: usize> SecurityGate<'a, N> {
    /// Create a new security gate backed by the given witness log.
    #[must_use]
    pub const fn new(witness_log: &'a WitnessLog<N>) -> Self {
        Self { witness_log }
    }

    /// Run a request through the full security pipeline.
    ///
    /// Pipeline:
    /// 1. P1 capability check (type + rights)
    /// 2. P2 policy validation (proof commitment if required)
    /// 3. Emit witness record
    /// 4. Return `GateResponse` with witness sequence
    ///
    /// On failure, emits a `ProofRejected` witness and returns the error.
    ///
    /// # Errors
    ///
    /// Returns [`SecurityError`] if any pipeline stage fails.
    pub fn check_and_execute(&self, request: &GateRequest) -> Result<GateResponse, SecurityError> {
        // Step 1: P1 capability check — type match
        if request.token.cap_type() != request.required_type {
            self.emit_rejection(request);
            return Err(SecurityError::CapabilityTypeMismatch);
        }

        // Step 1b: P1 capability check — rights subset
        if !request.token.has_rights(request.required_rights) {
            self.emit_rejection(request);
            return Err(SecurityError::InsufficientRights);
        }

        // Step 2: P2 policy validation — proof commitment
        let proof_tier = if let Some(commitment) = &request.proof_commitment {
            if commitment.is_zero() {
                self.emit_rejection(request);
                return Err(SecurityError::PolicyViolation);
            }
            2 // P2 was validated
        } else {
            1 // P1-only (no proof commitment needed)
        };

        // Step 3: Emit witness record for the allowed action
        let seq = self.emit_allowed(request, proof_tier);

        // Step 4: Return success
        Ok(GateResponse {
            witness_sequence: seq,
            proof_tier,
        })
    }

    /// Emit a witness record for an allowed operation.
    fn emit_allowed(&self, request: &GateRequest, proof_tier: u8) -> u64 {
        let mut record = WitnessRecord::zeroed();
        record.action_kind = request.action as u8;
        record.proof_tier = proof_tier;
        record.actor_partition_id = 0; // caller context not tracked here
        record.target_object_id = request.target_object_id;
        record.capability_hash = request.token.truncated_hash();
        record.timestamp_ns = request.timestamp_ns;
        self.witness_log.append(record)
    }

    /// Emit a `ProofRejected` witness record for a denied operation.
    fn emit_rejection(&self, request: &GateRequest) {
        let mut record = WitnessRecord::zeroed();
        record.action_kind = ActionKind::ProofRejected as u8;
        record.actor_partition_id = 0;
        record.target_object_id = request.target_object_id;
        record.capability_hash = request.token.truncated_hash();
        record.timestamp_ns = request.timestamp_ns;
        self.witness_log.append(record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(cap_type: CapType, rights: CapRights) -> CapToken {
        CapToken::new(1, cap_type, rights, 1)
    }

    #[test]
    fn test_gate_allows_valid_request() {
        let log = WitnessLog::<16>::new();
        let gate = SecurityGate::new(&log);

        let request = GateRequest {
            token: make_token(CapType::Partition, CapRights::READ | CapRights::WRITE),
            required_type: CapType::Partition,
            required_rights: CapRights::READ,
            proof_commitment: None,
            action: ActionKind::PartitionCreate,
            target_object_id: 42,
            timestamp_ns: 1000,
        };

        let response = gate.check_and_execute(&request).unwrap();
        assert_eq!(response.proof_tier, 1);
        assert_eq!(log.total_emitted(), 1);
    }

    #[test]
    fn test_gate_denies_wrong_type() {
        let log = WitnessLog::<16>::new();
        let gate = SecurityGate::new(&log);

        let request = GateRequest {
            token: make_token(CapType::Region, CapRights::READ),
            required_type: CapType::Partition,
            required_rights: CapRights::READ,
            proof_commitment: None,
            action: ActionKind::PartitionCreate,
            target_object_id: 42,
            timestamp_ns: 1000,
        };

        let err = gate.check_and_execute(&request).unwrap_err();
        assert_eq!(err, SecurityError::CapabilityTypeMismatch);
        // Should have emitted a ProofRejected witness
        assert_eq!(log.total_emitted(), 1);
        let record = log.get(0).unwrap();
        assert_eq!(record.action_kind, ActionKind::ProofRejected as u8);
    }

    #[test]
    fn test_gate_denies_insufficient_rights() {
        let log = WitnessLog::<16>::new();
        let gate = SecurityGate::new(&log);

        let request = GateRequest {
            token: make_token(CapType::Partition, CapRights::READ),
            required_type: CapType::Partition,
            required_rights: CapRights::READ | CapRights::WRITE,
            proof_commitment: None,
            action: ActionKind::PartitionCreate,
            target_object_id: 42,
            timestamp_ns: 1000,
        };

        let err = gate.check_and_execute(&request).unwrap_err();
        assert_eq!(err, SecurityError::InsufficientRights);
        assert_eq!(log.total_emitted(), 1);
    }

    #[test]
    fn test_gate_denies_zero_proof_commitment() {
        let log = WitnessLog::<16>::new();
        let gate = SecurityGate::new(&log);

        let request = GateRequest {
            token: make_token(CapType::Partition, CapRights::READ | CapRights::WRITE),
            required_type: CapType::Partition,
            required_rights: CapRights::READ,
            proof_commitment: Some(WitnessHash::ZERO),
            action: ActionKind::PartitionCreate,
            target_object_id: 42,
            timestamp_ns: 1000,
        };

        let err = gate.check_and_execute(&request).unwrap_err();
        assert_eq!(err, SecurityError::PolicyViolation);
        assert_eq!(log.total_emitted(), 1);
    }

    #[test]
    fn test_gate_allows_valid_proof_commitment() {
        let log = WitnessLog::<16>::new();
        let gate = SecurityGate::new(&log);

        let commitment = WitnessHash::from_bytes([0xAB; 32]);
        let request = GateRequest {
            token: make_token(CapType::Region, CapRights::READ | CapRights::WRITE),
            required_type: CapType::Region,
            required_rights: CapRights::WRITE,
            proof_commitment: Some(commitment),
            action: ActionKind::RegionCreate,
            target_object_id: 100,
            timestamp_ns: 2000,
        };

        let response = gate.check_and_execute(&request).unwrap();
        assert_eq!(response.proof_tier, 2);
        assert_eq!(log.total_emitted(), 1);
    }

    #[test]
    fn test_gate_pipeline_witness_sequence() {
        let log = WitnessLog::<16>::new();
        let gate = SecurityGate::new(&log);

        let make_req = |ts| GateRequest {
            token: make_token(CapType::Partition, CapRights::READ),
            required_type: CapType::Partition,
            required_rights: CapRights::READ,
            proof_commitment: None,
            action: ActionKind::PartitionCreate,
            target_object_id: 1,
            timestamp_ns: ts,
        };

        let r0 = gate.check_and_execute(&make_req(100)).unwrap();
        let r1 = gate.check_and_execute(&make_req(200)).unwrap();
        let r2 = gate.check_and_execute(&make_req(300)).unwrap();

        assert_eq!(r0.witness_sequence, 0);
        assert_eq!(r1.witness_sequence, 1);
        assert_eq!(r2.witness_sequence, 2);
        assert_eq!(log.total_emitted(), 3);
    }
}
