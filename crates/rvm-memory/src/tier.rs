//! Memory tier management per ADR-136.
//!
//! Implements the four-tier coherence-driven memory model:
//! Hot (tier 0), Warm (tier 1), Dormant (tier 2), Cold (tier 3).
//!
//! Tier placement is driven by the residency rule:
//!   `cut_value + recency_score > eviction_threshold`
//!
//! When the coherence engine is absent (DC-1), `cut_value` defaults to 0
//! and only `recency_score` drives tier placement against a static threshold.

use rvm_types::{OwnedRegionId, RvmError, RvmResult};

/// The four memory tiers defined in ADR-136.
///
/// This extends the 3-tier `MemoryTier` from `rvm-types` by adding the
/// Dormant tier that stores compressed reconstructable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Tier {
    /// Tier 0 -- Hot: per-core SRAM or L1/L2 cache-resident.
    /// Always resident during partition execution.
    Hot = 0,
    /// Tier 1 -- Warm: cluster-shared DRAM.
    /// Resident if `cut_value + recency_score > eviction_threshold`.
    Warm = 1,
    /// Tier 2 -- Dormant: compressed storage in main memory.
    /// Stored as witness checkpoint + delta compression; reconstructed on demand.
    Dormant = 2,
    /// Tier 3 -- Cold: RVF-backed archival on persistent storage.
    /// Accessed only during recovery or explicit restore. Never auto-promoted.
    Cold = 3,
}

impl Tier {
    /// Return the numeric tier index.
    #[must_use]
    pub const fn index(self) -> u8 {
        self as u8
    }

    /// Try to create a `Tier` from a raw `u8` value.
    #[must_use]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Hot),
            1 => Some(Self::Warm),
            2 => Some(Self::Dormant),
            3 => Some(Self::Cold),
            _ => None,
        }
    }
}

/// Static fallback thresholds for tier transitions when the coherence
/// engine is absent (DC-1). All values are in basis points (`0..=10_000`).
pub struct TierThresholds {
    /// Threshold for Hot -> Warm demotion.
    /// If `cut_value + recency_score` drops below this, demote from Hot.
    pub hot_to_warm: u16,
    /// Threshold for Warm -> Dormant demotion.
    pub warm_to_dormant: u16,
    /// Threshold for Dormant -> Cold demotion.
    pub dormant_to_cold: u16,
    /// Threshold for Warm -> Hot promotion.
    pub warm_to_hot: u16,
    /// Threshold for Dormant -> Warm promotion (triggers reconstruction).
    pub dormant_to_warm: u16,
}

impl TierThresholds {
    /// Conservative default thresholds for DC-1 (no coherence engine).
    pub const DEFAULT: Self = Self {
        hot_to_warm: 7_000,
        warm_to_dormant: 4_000,
        dormant_to_cold: 1_000,
        warm_to_hot: 8_000,
        dormant_to_warm: 5_000,
    };
}

/// Per-region metadata tracked by the tier manager.
#[derive(Debug, Clone, Copy)]
pub struct RegionTierState {
    /// The region identifier.
    pub region_id: OwnedRegionId,
    /// Current tier placement.
    pub tier: Tier,
    /// Epoch of last access (monotonically increasing).
    pub last_access_epoch: u32,
    /// Coherence graph cut-value for this region (basis points, `0..=10_000`).
    /// Defaults to 0 when coherence engine is absent (DC-1).
    pub cut_value: u16,
    /// Recency score (basis points, `0..=10_000`). Decays each epoch.
    pub recency_score: u16,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl RegionTierState {
    /// An empty (unoccupied) slot.
    const EMPTY: Self = Self {
        region_id: OwnedRegionId::new(0),
        tier: Tier::Warm,
        last_access_epoch: 0,
        cut_value: 0,
        recency_score: 0,
        occupied: false,
    };

    /// Compute the composite residency score: `cut_value + recency_score`.
    /// Saturates at `u16::MAX` to avoid overflow.
    #[must_use]
    pub const fn residency_score(self) -> u16 {
        self.cut_value.saturating_add(self.recency_score)
    }
}

/// Manages tier placement for a fixed set of memory regions.
///
/// `MAX_REGIONS` is the compile-time upper bound on tracked regions.
/// This avoids heap allocation and is suitable for `no_std` environments.
pub struct TierManager<const MAX_REGIONS: usize> {
    /// Per-region tier state, indexed by slot (not by region ID).
    regions: [RegionTierState; MAX_REGIONS],
    /// Number of occupied slots.
    count: usize,
    /// Tier thresholds (static fallback for DC-1).
    thresholds: TierThresholds,
    /// Current epoch for recency tracking.
    current_epoch: u32,
}

impl<const MAX_REGIONS: usize> Default for TierManager<MAX_REGIONS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_REGIONS: usize> TierManager<MAX_REGIONS> {
    /// Create a new `TierManager` with default DC-1 thresholds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            regions: [RegionTierState::EMPTY; MAX_REGIONS],
            count: 0,
            thresholds: TierThresholds::DEFAULT,
            current_epoch: 0,
        }
    }

    /// Create a new `TierManager` with custom thresholds.
    #[must_use]
    pub const fn with_thresholds(thresholds: TierThresholds) -> Self {
        Self {
            regions: [RegionTierState::EMPTY; MAX_REGIONS],
            count: 0,
            thresholds,
            current_epoch: 0,
        }
    }

    /// Return the number of tracked regions.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the current epoch.
    #[must_use]
    pub const fn current_epoch(&self) -> u32 {
        self.current_epoch
    }

    /// Advance the epoch counter. Call this once per scheduler epoch.
    pub fn advance_epoch(&mut self) {
        self.current_epoch = self.current_epoch.saturating_add(1);
    }

    /// Register a new region in the tier manager at the given initial tier.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the manager is at capacity.
    /// Returns [`RvmError::MemoryOverlap`] if the region is already registered.
    pub fn register(
        &mut self,
        region_id: OwnedRegionId,
        initial_tier: Tier,
    ) -> RvmResult<()> {
        if self.count >= MAX_REGIONS {
            return Err(RvmError::ResourceLimitExceeded);
        }
        // Check for duplicate registration.
        if self.find_slot(region_id).is_some() {
            return Err(RvmError::MemoryOverlap);
        }
        // Find the first empty slot.
        for slot in &mut self.regions {
            if !slot.occupied {
                *slot = RegionTierState {
                    region_id,
                    tier: initial_tier,
                    last_access_epoch: self.current_epoch,
                    cut_value: 0,
                    recency_score: 5_000, // Start at midpoint
                    occupied: true,
                };
                self.count += 1;
                return Ok(());
            }
        }
        Err(RvmError::ResourceLimitExceeded)
    }

    /// Unregister a region from the tier manager.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the region is not tracked.
    pub fn unregister(&mut self, region_id: OwnedRegionId) -> RvmResult<()> {
        match self.find_slot(region_id) {
            Some(idx) => {
                self.regions[idx] = RegionTierState::EMPTY;
                self.count -= 1;
                Ok(())
            }
            None => Err(RvmError::PartitionNotFound),
        }
    }

    /// Record an access to the given region, updating its recency score.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the region is not tracked.
    pub fn record_access(&mut self, region_id: OwnedRegionId) -> RvmResult<()> {
        match self.find_slot(region_id) {
            Some(idx) => {
                self.regions[idx].last_access_epoch = self.current_epoch;
                // Boost recency score on access, saturate at 10_000.
                self.regions[idx].recency_score =
                    self.regions[idx].recency_score.saturating_add(1_000).min(10_000);
                Ok(())
            }
            None => Err(RvmError::PartitionNotFound),
        }
    }

    /// Update the cut value for a region (from the coherence engine).
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the region is not tracked.
    pub fn update_cut_value(
        &mut self,
        region_id: OwnedRegionId,
        cut_value: u16,
    ) -> RvmResult<()> {
        match self.find_slot(region_id) {
            Some(idx) => {
                self.regions[idx].cut_value = cut_value.min(10_000);
                Ok(())
            }
            None => Err(RvmError::PartitionNotFound),
        }
    }

    /// Promote a region to a higher (lower-numbered) tier.
    ///
    /// Returns the previous tier on success.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the region is not tracked.
    /// Returns [`RvmError::InvalidTierTransition`] if the target tier is not
    /// higher than the current tier, or if promoting from Cold.
    /// Returns [`RvmError::CoherenceBelowThreshold`] if the residency score
    /// does not meet the promotion threshold.
    pub fn promote(
        &mut self,
        region_id: OwnedRegionId,
        target_tier: Tier,
    ) -> RvmResult<Tier> {
        let idx = self
            .find_slot(region_id)
            .ok_or(RvmError::PartitionNotFound)?;
        let current = self.regions[idx].tier;

        // Target must be a higher (lower-numbered) tier.
        if target_tier >= current {
            return Err(RvmError::InvalidTierTransition);
        }
        // Cold regions never auto-promote (ADR-136: accessed only during recovery).
        if current == Tier::Cold {
            return Err(RvmError::InvalidTierTransition);
        }
        // Validate the residency rule for the target tier.
        let score = self.regions[idx].residency_score();
        let threshold = self.promotion_threshold(target_tier);
        if score < threshold {
            return Err(RvmError::CoherenceBelowThreshold);
        }

        let old_tier = self.regions[idx].tier;
        self.regions[idx].tier = target_tier;
        self.regions[idx].last_access_epoch = self.current_epoch;
        Ok(old_tier)
    }

    /// Demote a region to a lower (higher-numbered) tier.
    ///
    /// Returns the previous tier on success.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::PartitionNotFound`] if the region is not tracked.
    /// Returns [`RvmError::InvalidTierTransition`] if the target tier is not
    /// lower than the current tier.
    pub fn demote(
        &mut self,
        region_id: OwnedRegionId,
        target_tier: Tier,
    ) -> RvmResult<Tier> {
        let idx = self
            .find_slot(region_id)
            .ok_or(RvmError::PartitionNotFound)?;
        let current = self.regions[idx].tier;

        // Target must be a lower (higher-numbered) tier.
        if target_tier <= current {
            return Err(RvmError::InvalidTierTransition);
        }

        let old_tier = self.regions[idx].tier;
        self.regions[idx].tier = target_tier;
        Ok(old_tier)
    }

    /// Return the current tier state for a region, if tracked.
    #[must_use]
    pub fn get(&self, region_id: OwnedRegionId) -> Option<&RegionTierState> {
        self.find_slot(region_id).map(|idx| &self.regions[idx])
    }

    /// Decay recency scores for all tracked regions by the given amount
    /// (in basis points). Call this once per epoch to age out stale regions.
    pub fn decay_recency(&mut self, decay_amount: u16) {
        for slot in &mut self.regions {
            if slot.occupied {
                slot.recency_score = slot.recency_score.saturating_sub(decay_amount);
            }
        }
    }

    /// Identify regions that should be demoted based on current thresholds.
    ///
    /// Returns (`region_id`, `recommended_target_tier`) pairs.
    /// Caller is responsible for acting on recommendations (e.g., triggering
    /// compression for Dormant demotion).
    ///
    /// `out` is a caller-provided buffer; returns the number of entries written.
    pub fn find_demotion_candidates(
        &self,
        out: &mut [(OwnedRegionId, Tier)],
    ) -> usize {
        let mut written = 0;
        for slot in &self.regions {
            if !slot.occupied || written >= out.len() {
                continue;
            }
            let score = slot.residency_score();
            let target = match slot.tier {
                Tier::Hot if score < self.thresholds.hot_to_warm => Some(Tier::Warm),
                Tier::Warm if score < self.thresholds.warm_to_dormant => Some(Tier::Dormant),
                Tier::Dormant if score < self.thresholds.dormant_to_cold => Some(Tier::Cold),
                _ => None,
            };
            if let Some(target_tier) = target {
                out[written] = (slot.region_id, target_tier);
                written += 1;
            }
        }
        written
    }

    // --- Private helpers ---

    /// Find the slot index for a given region ID.
    fn find_slot(&self, region_id: OwnedRegionId) -> Option<usize> {
        self.regions
            .iter()
            .position(|s| s.occupied && s.region_id == region_id)
    }

    /// Return the promotion threshold for a given target tier.
    const fn promotion_threshold(&self, target: Tier) -> u16 {
        match target {
            Tier::Hot => self.thresholds.warm_to_hot,
            Tier::Warm => self.thresholds.dormant_to_warm,
            // Dormant and Cold are demotion targets, not promotion targets.
            Tier::Dormant | Tier::Cold => u16::MAX,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(id: u64) -> OwnedRegionId {
        OwnedRegionId::new(id)
    }

    #[test]
    fn tier_from_u8_round_trips() {
        for val in 0..=3u8 {
            let tier = Tier::from_u8(val).unwrap();
            assert_eq!(tier.index(), val);
        }
        assert!(Tier::from_u8(4).is_none());
        assert!(Tier::from_u8(255).is_none());
    }

    #[test]
    fn tier_ordering() {
        assert!(Tier::Hot < Tier::Warm);
        assert!(Tier::Warm < Tier::Dormant);
        assert!(Tier::Dormant < Tier::Cold);
    }

    #[test]
    fn register_and_get() {
        let mut mgr = TierManager::<8>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(mgr.count(), 1);

        let state = mgr.get(rid(1)).unwrap();
        assert_eq!(state.tier, Tier::Warm);
        assert_eq!(state.region_id, rid(1));
        assert!(state.occupied);
    }

    #[test]
    fn register_duplicate_fails() {
        let mut mgr = TierManager::<8>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(mgr.register(rid(1), Tier::Hot), Err(RvmError::MemoryOverlap));
    }

    #[test]
    fn register_at_capacity_fails() {
        let mut mgr = TierManager::<2>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        mgr.register(rid(2), Tier::Warm).unwrap();
        assert_eq!(
            mgr.register(rid(3), Tier::Warm),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn unregister_frees_slot() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        mgr.register(rid(2), Tier::Hot).unwrap();
        assert_eq!(mgr.count(), 2);

        mgr.unregister(rid(1)).unwrap();
        assert_eq!(mgr.count(), 1);
        assert!(mgr.get(rid(1)).is_none());

        // Can re-register into freed slot.
        mgr.register(rid(3), Tier::Dormant).unwrap();
        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn unregister_nonexistent_fails() {
        let mut mgr = TierManager::<4>::new();
        assert_eq!(mgr.unregister(rid(99)), Err(RvmError::PartitionNotFound));
    }

    #[test]
    fn promote_warm_to_hot() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        // Default recency_score is 5_000, cut_value is 0.
        // warm_to_hot threshold is 8_000, so score=5_000 is insufficient.
        assert_eq!(
            mgr.promote(rid(1), Tier::Hot),
            Err(RvmError::CoherenceBelowThreshold)
        );

        // Boost cut_value to make it pass.
        mgr.update_cut_value(rid(1), 4_000).unwrap();
        // Now score = 4_000 + 5_000 = 9_000 > 8_000.
        let old = mgr.promote(rid(1), Tier::Hot).unwrap();
        assert_eq!(old, Tier::Warm);
        assert_eq!(mgr.get(rid(1)).unwrap().tier, Tier::Hot);
    }

    #[test]
    fn promote_dormant_to_warm() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Dormant).unwrap();
        // Default recency is 5_000, dormant_to_warm threshold is 5_000.
        // 5_000 >= 5_000, so it should pass.
        let old = mgr.promote(rid(1), Tier::Warm).unwrap();
        assert_eq!(old, Tier::Dormant);
        assert_eq!(mgr.get(rid(1)).unwrap().tier, Tier::Warm);
    }

    #[test]
    fn promote_cold_always_fails() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Cold).unwrap();
        mgr.update_cut_value(rid(1), 10_000).unwrap();
        assert_eq!(
            mgr.promote(rid(1), Tier::Dormant),
            Err(RvmError::InvalidTierTransition)
        );
    }

    #[test]
    fn promote_same_tier_fails() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(
            mgr.promote(rid(1), Tier::Warm),
            Err(RvmError::InvalidTierTransition)
        );
    }

    #[test]
    fn promote_to_lower_tier_fails() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(
            mgr.promote(rid(1), Tier::Dormant),
            Err(RvmError::InvalidTierTransition)
        );
    }

    #[test]
    fn demote_hot_to_warm() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Hot).unwrap();
        let old = mgr.demote(rid(1), Tier::Warm).unwrap();
        assert_eq!(old, Tier::Hot);
        assert_eq!(mgr.get(rid(1)).unwrap().tier, Tier::Warm);
    }

    #[test]
    fn demote_to_higher_tier_fails() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(
            mgr.demote(rid(1), Tier::Hot),
            Err(RvmError::InvalidTierTransition)
        );
    }

    #[test]
    fn demote_same_tier_fails() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(
            mgr.demote(rid(1), Tier::Warm),
            Err(RvmError::InvalidTierTransition)
        );
    }

    #[test]
    fn demote_warm_to_cold_skipping_dormant() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        let old = mgr.demote(rid(1), Tier::Cold).unwrap();
        assert_eq!(old, Tier::Warm);
        assert_eq!(mgr.get(rid(1)).unwrap().tier, Tier::Cold);
    }

    #[test]
    fn record_access_boosts_recency() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        let before = mgr.get(rid(1)).unwrap().recency_score;

        mgr.record_access(rid(1)).unwrap();
        let after = mgr.get(rid(1)).unwrap().recency_score;
        assert!(after > before);
    }

    #[test]
    fn record_access_nonexistent_fails() {
        let mut mgr = TierManager::<4>::new();
        assert_eq!(mgr.record_access(rid(99)), Err(RvmError::PartitionNotFound));
    }

    #[test]
    fn decay_recency_reduces_scores() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        let before = mgr.get(rid(1)).unwrap().recency_score;

        mgr.decay_recency(1_000);
        let after = mgr.get(rid(1)).unwrap().recency_score;
        assert_eq!(after, before - 1_000);
    }

    #[test]
    fn decay_recency_saturates_at_zero() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        mgr.decay_recency(20_000); // Way more than current score.
        assert_eq!(mgr.get(rid(1)).unwrap().recency_score, 0);
    }

    #[test]
    fn find_demotion_candidates() {
        let mut mgr = TierManager::<8>::new();
        mgr.register(rid(1), Tier::Hot).unwrap();
        mgr.register(rid(2), Tier::Warm).unwrap();
        mgr.register(rid(3), Tier::Dormant).unwrap();

        // Decay all recency scores heavily so they drop below thresholds.
        mgr.decay_recency(10_000);

        let mut buf = [(OwnedRegionId::new(0), Tier::Hot); 8];
        let n = mgr.find_demotion_candidates(&mut buf);

        // All three should be candidates for demotion.
        assert_eq!(n, 3);

        // Verify each demotion target is correct.
        let candidates: &[(OwnedRegionId, Tier)] = &buf[..n];
        assert!(candidates.iter().any(|(id, t)| *id == rid(1) && *t == Tier::Warm));
        assert!(candidates.iter().any(|(id, t)| *id == rid(2) && *t == Tier::Dormant));
        assert!(candidates.iter().any(|(id, t)| *id == rid(3) && *t == Tier::Cold));
    }

    #[test]
    fn advance_epoch() {
        let mut mgr = TierManager::<4>::new();
        assert_eq!(mgr.current_epoch(), 0);
        mgr.advance_epoch();
        assert_eq!(mgr.current_epoch(), 1);
        mgr.advance_epoch();
        assert_eq!(mgr.current_epoch(), 2);
    }

    #[test]
    fn residency_score_computation() {
        let state = RegionTierState {
            region_id: rid(1),
            tier: Tier::Warm,
            last_access_epoch: 0,
            cut_value: 3_000,
            recency_score: 4_000,
            occupied: true,
        };
        assert_eq!(state.residency_score(), 7_000);
    }

    #[test]
    fn residency_score_saturates() {
        let state = RegionTierState {
            region_id: rid(1),
            tier: Tier::Warm,
            last_access_epoch: 0,
            cut_value: 60_000,
            recency_score: 60_000,
            occupied: true,
        };
        assert_eq!(state.residency_score(), u16::MAX);
    }

    #[test]
    fn residency_score_no_overflow_within_range() {
        let state = RegionTierState {
            region_id: rid(1),
            tier: Tier::Warm,
            last_access_epoch: 0,
            cut_value: 10_000,
            recency_score: 10_000,
            occupied: true,
        };
        assert_eq!(state.residency_score(), 20_000);
    }

    #[test]
    fn update_cut_value_clamps() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        mgr.update_cut_value(rid(1), 50_000).unwrap();
        assert_eq!(mgr.get(rid(1)).unwrap().cut_value, 10_000);
    }

    // ---------------------------------------------------------------
    // DC-1 static fallback: coherence-absent behavior
    // ---------------------------------------------------------------

    #[test]
    fn dc1_fallback_cut_value_stays_zero_without_coherence() {
        // When the coherence engine is absent, cut_value defaults to 0.
        // Only recency_score drives tier placement.
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();

        let state = mgr.get(rid(1)).unwrap();
        assert_eq!(state.cut_value, 0);
        // Residency score = 0 + 5_000 = 5_000.
        assert_eq!(state.residency_score(), 5_000);
    }

    #[test]
    fn dc1_fallback_promotion_blocked_by_low_recency() {
        // Without coherence engine, warm->hot requires score >= 8_000.
        // Default recency=5_000, cut_value=0, score=5_000 < 8_000.
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(
            mgr.promote(rid(1), Tier::Hot),
            Err(RvmError::CoherenceBelowThreshold)
        );
    }

    #[test]
    fn dc1_fallback_promotion_possible_with_high_recency() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();

        // Boost recency to 8_000 by accessing 3 times
        // (5_000 + 1_000 + 1_000 + 1_000 = 8_000)
        mgr.record_access(rid(1)).unwrap();
        mgr.record_access(rid(1)).unwrap();
        mgr.record_access(rid(1)).unwrap();
        let state = mgr.get(rid(1)).unwrap();
        assert_eq!(state.recency_score, 8_000);
        assert_eq!(state.residency_score(), 8_000); // cut_value still 0

        // Now promotion to Hot should succeed (8_000 >= 8_000 threshold).
        let old = mgr.promote(rid(1), Tier::Hot).unwrap();
        assert_eq!(old, Tier::Warm);
    }

    #[test]
    fn dc1_fallback_demotion_on_decay() {
        let mut mgr = TierManager::<8>::new();
        mgr.register(rid(1), Tier::Hot).unwrap();

        // Default recency = 5_000, cut_value = 0.
        // Hot->Warm threshold is 7_000. Since score=5_000 < 7_000, region
        // should be a demotion candidate immediately.
        let mut buf = [(OwnedRegionId::new(0), Tier::Hot); 8];
        let n = mgr.find_demotion_candidates(&mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0].0, rid(1));
        assert_eq!(buf[0].1, Tier::Warm);
    }

    #[test]
    fn dc1_fallback_warm_to_dormant_demotion_after_decay() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();

        // Decay recency to below warm_to_dormant threshold (4_000).
        // Initial recency=5_000, decay by 2_000 -> 3_000 < 4_000.
        mgr.decay_recency(2_000);
        let mut buf = [(OwnedRegionId::new(0), Tier::Hot); 4];
        let n = mgr.find_demotion_candidates(&mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0].0, rid(1));
        assert_eq!(buf[0].1, Tier::Dormant);
    }

    #[test]
    fn dc1_fallback_dormant_to_cold_demotion() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Dormant).unwrap();

        // Decay recency to below dormant_to_cold threshold (1_000).
        mgr.decay_recency(5_000); // recency 0
        let mut buf = [(OwnedRegionId::new(0), Tier::Hot); 4];
        let n = mgr.find_demotion_candidates(&mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0].0, rid(1));
        assert_eq!(buf[0].1, Tier::Cold);
    }

    #[test]
    fn recency_access_saturates_at_10000() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Warm).unwrap();

        // Access many times to saturate.
        for _ in 0..20 {
            mgr.record_access(rid(1)).unwrap();
        }
        assert_eq!(mgr.get(rid(1)).unwrap().recency_score, 10_000);
    }

    #[test]
    fn epoch_advance_is_monotonic() {
        let mut mgr = TierManager::<4>::new();
        for expected in 0..10u32 {
            assert_eq!(mgr.current_epoch(), expected);
            mgr.advance_epoch();
        }
        assert_eq!(mgr.current_epoch(), 10);
    }

    #[test]
    fn registered_region_records_access_epoch() {
        let mut mgr = TierManager::<4>::new();
        mgr.advance_epoch();
        mgr.advance_epoch(); // epoch = 2
        mgr.register(rid(1), Tier::Warm).unwrap();
        assert_eq!(mgr.get(rid(1)).unwrap().last_access_epoch, 2);

        mgr.advance_epoch(); // epoch = 3
        mgr.record_access(rid(1)).unwrap();
        assert_eq!(mgr.get(rid(1)).unwrap().last_access_epoch, 3);
    }

    #[test]
    fn find_demotion_candidates_respects_buffer_size() {
        let mut mgr = TierManager::<8>::new();
        for i in 1..=5u64 {
            mgr.register(rid(i), Tier::Hot).unwrap();
        }
        // All 5 should be demotion candidates with default scores.
        // But we only provide a buffer of size 2.
        let mut buf = [(OwnedRegionId::new(0), Tier::Hot); 2];
        let n = mgr.find_demotion_candidates(&mut buf);
        assert_eq!(n, 2); // Only 2 fit.
    }

    #[test]
    fn cold_region_not_a_demotion_candidate() {
        let mut mgr = TierManager::<4>::new();
        mgr.register(rid(1), Tier::Cold).unwrap();
        mgr.decay_recency(10_000);

        let mut buf = [(OwnedRegionId::new(0), Tier::Hot); 4];
        let n = mgr.find_demotion_candidates(&mut buf);
        // Cold has no lower tier, so not a candidate.
        assert_eq!(n, 0);
    }

    #[test]
    fn custom_thresholds() {
        let thresholds = TierThresholds {
            hot_to_warm: 9_000,
            warm_to_dormant: 6_000,
            dormant_to_cold: 3_000,
            warm_to_hot: 9_500,
            dormant_to_warm: 7_000,
        };
        let mgr = TierManager::<4>::with_thresholds(thresholds);
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn update_cut_value_nonexistent_fails() {
        let mut mgr = TierManager::<4>::new();
        assert_eq!(
            mgr.update_cut_value(rid(99), 5_000),
            Err(RvmError::PartitionNotFound)
        );
    }

    #[test]
    fn promote_nonexistent_fails() {
        let mut mgr = TierManager::<4>::new();
        assert_eq!(
            mgr.promote(rid(99), Tier::Hot),
            Err(RvmError::PartitionNotFound)
        );
    }

    #[test]
    fn demote_nonexistent_fails() {
        let mut mgr = TierManager::<4>::new();
        assert_eq!(
            mgr.demote(rid(99), Tier::Cold),
            Err(RvmError::PartitionNotFound)
        );
    }
}
