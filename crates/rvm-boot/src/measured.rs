//! Measured boot -- hash-chain accumulation for attestation (ADR-142).
//!
//! Each boot phase extends the measurement state by chaining the
//! phase's output hash into a running accumulator. The final digest
//! serves as the platform attestation root.
//!
//! When the `crypto-sha256` feature is enabled (default), SHA-256 is
//! used for the measurement extension. When disabled, the legacy FNV-1a
//! overlapping-window scheme is used instead.

#[cfg(not(feature = "crypto-sha256"))]
use rvm_types::fnv1a_64;

use crate::sequence::BootStage;

/// Measured boot state that accumulates a hash chain across boot phases.
///
/// Before each phase executes, it hashes the next phase's code/config
/// and extends the measurement. The final accumulator serves as the
/// attestation digest for the entire boot sequence.
#[derive(Debug)]
pub struct MeasuredBootState {
    /// Running accumulator: SHA-256 chain (or FNV-1a fallback) for `no_std`.
    accumulator: [u8; 32],
    /// Number of measurements extended so far.
    measurement_count: u32,
    /// Per-phase measurement hashes for audit replay.
    phase_hashes: [[u8; 32]; 7],
}

impl MeasuredBootState {
    /// Create a new measured boot state with a zeroed accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            accumulator: [0u8; 32],
            measurement_count: 0,
            phase_hashes: [[0u8; 32]; 7],
        }
    }

    /// Extend the measurement chain with a phase's output hash using SHA-256.
    ///
    /// The new accumulator is `SHA-256(accumulator || phase_index || hash_bytes)`.
    #[cfg(feature = "crypto-sha256")]
    pub fn extend_measurement(&mut self, phase: BootStage, hash_bytes: &[u8; 32]) {
        use sha2::{Sha256, Digest};

        let idx = phase as usize;
        self.phase_hashes[idx] = *hash_bytes;

        let mut hasher = Sha256::new();
        hasher.update(self.accumulator);
        hasher.update([idx as u8]);
        hasher.update(hash_bytes);
        let digest = hasher.finalize();

        self.accumulator.copy_from_slice(&digest);
        self.measurement_count += 1;
    }

    /// Extend the measurement chain with a phase's output hash using FNV-1a
    /// (legacy fallback when `crypto-sha256` is disabled).
    ///
    /// The new accumulator is computed from overlapping FNV-1a windows over
    /// `accumulator || phase_index || hash_bytes`.
    #[cfg(not(feature = "crypto-sha256"))]
    pub fn extend_measurement(&mut self, phase: BootStage, hash_bytes: &[u8; 32]) {
        let idx = phase as usize;
        self.phase_hashes[idx] = *hash_bytes;

        // Build input: current accumulator + phase index + new hash
        let mut input = [0u8; 65]; // 32 + 1 + 32
        input[..32].copy_from_slice(&self.accumulator);
        input[32] = idx as u8;
        input[33..65].copy_from_slice(hash_bytes);

        // Chain using four FNV-1a passes to fill 32 bytes
        let h0 = fnv1a_64(&input);
        let h1 = fnv1a_64(&input[8..]);
        let h2 = fnv1a_64(&input[16..]);
        let h3 = fnv1a_64(&input[24..]);

        self.accumulator[..8].copy_from_slice(&h0.to_le_bytes());
        self.accumulator[8..16].copy_from_slice(&h1.to_le_bytes());
        self.accumulator[16..24].copy_from_slice(&h2.to_le_bytes());
        self.accumulator[24..32].copy_from_slice(&h3.to_le_bytes());

        self.measurement_count += 1;
    }

    /// Return the current attestation digest (the accumulated hash chain).
    #[must_use]
    pub const fn get_attestation_digest(&self) -> [u8; 32] {
        self.accumulator
    }

    /// Return the number of measurements extended so far.
    #[must_use]
    pub const fn measurement_count(&self) -> u32 {
        self.measurement_count
    }

    /// Return the individual measurement hash for a specific phase.
    #[must_use]
    pub const fn phase_hash(&self, phase: BootStage) -> &[u8; 32] {
        &self.phase_hashes[phase as usize]
    }

    /// Check whether the accumulator is still in its initial zeroed state.
    #[must_use]
    pub fn is_virgin(&self) -> bool {
        self.accumulator == [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let state = MeasuredBootState::new();
        assert!(state.is_virgin());
        assert_eq!(state.measurement_count(), 0);
        assert_eq!(state.get_attestation_digest(), [0u8; 32]);
    }

    #[test]
    fn test_single_extension() {
        let mut state = MeasuredBootState::new();
        let hash = [0xAA_u8; 32];
        state.extend_measurement(BootStage::ResetVector, &hash);

        assert!(!state.is_virgin());
        assert_eq!(state.measurement_count(), 1);
        assert_ne!(state.get_attestation_digest(), [0u8; 32]);
    }

    #[test]
    fn test_chain_determinism() {
        let mut s1 = MeasuredBootState::new();
        let mut s2 = MeasuredBootState::new();
        let hash = [0xBB_u8; 32];

        s1.extend_measurement(BootStage::ResetVector, &hash);
        s2.extend_measurement(BootStage::ResetVector, &hash);

        assert_eq!(s1.get_attestation_digest(), s2.get_attestation_digest());
    }

    #[test]
    fn test_chain_sensitivity() {
        let mut s1 = MeasuredBootState::new();
        let mut s2 = MeasuredBootState::new();

        s1.extend_measurement(BootStage::ResetVector, &[0xAA; 32]);
        s2.extend_measurement(BootStage::ResetVector, &[0xBB; 32]);

        assert_ne!(s1.get_attestation_digest(), s2.get_attestation_digest());
    }

    #[test]
    fn test_phase_ordering_matters() {
        let mut s1 = MeasuredBootState::new();
        let mut s2 = MeasuredBootState::new();

        let h1 = [0x11_u8; 32];
        let h2 = [0x22_u8; 32];

        s1.extend_measurement(BootStage::ResetVector, &h1);
        s1.extend_measurement(BootStage::HardwareDetect, &h2);

        s2.extend_measurement(BootStage::ResetVector, &h2);
        s2.extend_measurement(BootStage::HardwareDetect, &h1);

        assert_ne!(s1.get_attestation_digest(), s2.get_attestation_digest());
    }

    #[test]
    fn test_full_measurement_chain() {
        let mut state = MeasuredBootState::new();
        let stages = BootStage::all();

        for (i, &stage) in stages.iter().enumerate() {
            let hash = [i as u8; 32];
            state.extend_measurement(stage, &hash);
        }

        assert_eq!(state.measurement_count(), 7);
        assert!(!state.is_virgin());

        // Verify individual phase hashes were recorded
        for (i, &stage) in stages.iter().enumerate() {
            assert_eq!(*state.phase_hash(stage), [i as u8; 32]);
        }
    }

    #[test]
    fn test_each_extension_changes_digest() {
        let mut state = MeasuredBootState::new();
        let mut prev = state.get_attestation_digest();

        let stages = BootStage::all();
        for (i, &stage) in stages.iter().enumerate() {
            state.extend_measurement(stage, &[i as u8; 32]);
            let current = state.get_attestation_digest();
            assert_ne!(current, prev, "digest unchanged after stage {}", stage.name());
            prev = current;
        }
    }
}
