//! Capability table implementation.
//!
//! Each partition has a capability table that stores its held capabilities.
//! The table uses a fixed-size array with generation counters for stale
//! handle detection. No allocation in `no_std` environments.

use crate::error::{CapError, CapResult};
use crate::DEFAULT_CAP_TABLE_CAPACITY;
use rvm_types::{CapRights, CapToken, CapType, PartitionId};

/// A slot in the capability table.
///
/// Each slot holds either a valid capability or is marked as free for reuse.
/// Generation counters prevent stale handle access after deallocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapSlot {
    /// The capability token (valid when `generation != 0`).
    pub token: CapToken,
    /// Generation counter for stale handle detection.
    ///
    /// Generation 0 is the **invalid sentinel**: a slot with `generation == 0`
    /// is empty/free. Live slots always have `generation >= 1`, and the
    /// counter skips 0 on wrap-around (see [`invalidate`](Self::invalidate)).
    ///
    /// # Security note
    ///
    /// This is a u32, giving a 2^32 cycle forgery window: if an attacker
    /// can cause exactly 2^32 allocate/free cycles on a single slot, a
    /// stale handle could alias a new capability. In practice this is
    /// infeasible (would require ~4 billion operations on one slot), and
    /// widening to u64 would double `CapSlot` size and break the memory
    /// layout. Accepted as a low-severity residual risk.
    pub generation: u32,
    /// The partition that owns this capability.
    pub owner: PartitionId,
    /// Delegation depth (0 = root capability).
    pub depth: u8,
    /// Parent slot index (`u32::MAX` if root).
    pub parent_index: u32,
    /// Badge value for identifying the granting chain.
    pub badge: u64,
}

impl CapSlot {
    /// Creates an empty (invalid) slot.
    ///
    /// Empty slots have `generation == 0`, which is the invalid sentinel.
    #[inline]
    #[must_use]
    const fn empty() -> Self {
        Self {
            token: CapToken::new(0, CapType::Region, CapRights::empty(), 0),
            generation: 0,
            owner: PartitionId::new(0),
            depth: 0,
            parent_index: u32::MAX,
            badge: 0,
        }
    }

    /// Returns true if this slot is currently valid (in use).
    #[inline]
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.generation != 0
    }

    /// Returns true if this slot matches the given generation.
    #[inline]
    #[must_use]
    pub const fn matches(&self, generation: u32) -> bool {
        self.is_valid() && self.generation == generation
    }

    /// Invalidates this slot, bumping the generation counter for the
    /// next allocation and then clearing it to 0 (the free sentinel).
    ///
    /// The bumped generation is stored in `parent_index` (unused while
    /// the slot is free) so that the next `insert_*` call can recover it.
    ///
    /// # Security
    ///
    /// Generation 0 is the invalid sentinel. The counter skips 0 on
    /// wrap-around so that a re-allocated slot never gets generation 0.
    #[inline]
    pub fn invalidate(&mut self) {
        let next_gen = self.generation.wrapping_add(1);
        // Skip generation 0 (the free sentinel) to prevent aliasing.
        let safe_gen = if next_gen == 0 { 1 } else { next_gen };
        // Stash the next generation in parent_index while the slot is free.
        self.parent_index = safe_gen;
        // Mark the slot as free.
        self.generation = 0;
    }

    /// Recover the next generation counter for a free slot.
    ///
    /// For fresh (never-used) slots this returns 1 (since generation 0
    /// is the invalid sentinel). For previously-invalidated slots, the
    /// stashed value from `parent_index` is returned.
    #[inline]
    #[must_use]
    const fn next_generation(&self) -> u32 {
        // Fresh slots have parent_index == u32::MAX and generation == 0.
        // Invalidated slots have the next-gen stashed in parent_index.
        if self.generation != 0 {
            // Slot is occupied -- shouldn't be called, but return current.
            self.generation
        } else if self.parent_index == u32::MAX {
            // Fresh slot, never allocated. First valid generation is 1.
            1
        } else {
            // Previously invalidated: parent_index holds the stashed gen.
            self.parent_index
        }
    }
}

/// Fixed-size capability table for a partition.
///
/// Uses const generic `N` for the maximum number of capability slots.
/// No heap allocation: backed by a `[CapSlot; N]` array.
pub struct CapabilityTable<const N: usize = DEFAULT_CAP_TABLE_CAPACITY> {
    /// The slot array.
    slots: [CapSlot; N],
    /// Number of currently valid entries.
    count: usize,
    /// Hint for the next free slot (optimization).
    free_hint: usize,
}

impl<const N: usize> core::fmt::Debug for CapabilityTable<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CapabilityTable")
            .field("count", &self.count)
            .field("capacity", &N)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> CapabilityTable<N> {
    /// Creates a new empty capability table.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [CapSlot::empty(); N],
            count: 0,
            free_hint: 0,
        }
    }

    /// Returns the table capacity.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Returns the number of valid entries.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the table has no valid entries.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns true if the table is full.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.count >= N
    }

    /// Inserts a root capability. Returns `(index, generation)`.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::TableFull`] if no free slot is available.
    #[allow(clippy::cast_possible_truncation)]
    pub fn insert_root(
        &mut self,
        token: CapToken,
        owner: PartitionId,
        badge: u64,
    ) -> CapResult<(u32, u32)> {
        let index = self.find_free_slot()?;
        let generation = self.slots[index].next_generation();

        self.slots[index] = CapSlot {
            token,
            generation,
            owner,
            depth: 0,
            parent_index: u32::MAX,
            badge,
        };
        self.count += 1;

        Ok((index as u32, generation))
    }

    /// Inserts a derived capability. Returns `(index, generation)`.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::TableFull`] if no free slot is available.
    #[allow(clippy::cast_possible_truncation)]
    pub fn insert_derived(
        &mut self,
        token: CapToken,
        owner: PartitionId,
        depth: u8,
        parent_index: u32,
        badge: u64,
    ) -> CapResult<(u32, u32)> {
        let index = self.find_free_slot()?;
        let generation = self.slots[index].next_generation();

        self.slots[index] = CapSlot {
            token,
            generation,
            owner,
            depth,
            parent_index,
            badge,
        };
        self.count += 1;

        Ok((index as u32, generation))
    }

    /// Looks up a slot by index and generation.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::InvalidHandle`] if the index is out of bounds or the slot is empty.
    /// Returns [`CapError::StaleHandle`] if the generation does not match.
    #[inline]
    pub fn lookup(&self, index: u32, generation: u32) -> CapResult<&CapSlot> {
        let idx = index as usize;
        if idx >= N {
            return Err(CapError::InvalidHandle);
        }
        let slot = &self.slots[idx];
        if !slot.is_valid() {
            return Err(CapError::InvalidHandle);
        }
        if slot.generation != generation {
            return Err(CapError::StaleHandle);
        }
        Ok(slot)
    }

    /// Looks up a slot mutably by index and generation.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::InvalidHandle`] if the index is out of bounds or the slot is empty.
    /// Returns [`CapError::StaleHandle`] if the generation does not match.
    pub fn lookup_mut(&mut self, index: u32, generation: u32) -> CapResult<&mut CapSlot> {
        let idx = index as usize;
        if idx >= N {
            return Err(CapError::InvalidHandle);
        }
        let slot = &mut self.slots[idx];
        if !slot.is_valid() {
            return Err(CapError::InvalidHandle);
        }
        if slot.generation != generation {
            return Err(CapError::StaleHandle);
        }
        Ok(slot)
    }

    /// Removes a capability by index and generation.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::InvalidHandle`] if the index is out of bounds or the slot is empty.
    /// Returns [`CapError::StaleHandle`] if the generation does not match.
    pub fn remove(&mut self, index: u32, generation: u32) -> CapResult<()> {
        let idx = index as usize;
        if idx >= N {
            return Err(CapError::InvalidHandle);
        }
        let slot = &mut self.slots[idx];
        if !slot.is_valid() {
            return Err(CapError::InvalidHandle);
        }
        if slot.generation != generation {
            return Err(CapError::StaleHandle);
        }
        slot.invalidate();
        self.count -= 1;
        if idx < self.free_hint {
            self.free_hint = idx;
        }
        Ok(())
    }

    /// Invalidates a slot by index without generation check (internal revocation).
    pub(crate) fn force_invalidate(&mut self, index: u32) {
        let idx = index as usize;
        if idx < N && self.slots[idx].is_valid() {
            self.slots[idx].invalidate();
            self.count -= 1;
            if idx < self.free_hint {
                self.free_hint = idx;
            }
        }
    }

    /// Returns an iterator over all valid entries as `(index, &CapSlot)`.
    #[allow(clippy::cast_possible_truncation)]
    pub fn iter(&self) -> impl Iterator<Item = (u32, &CapSlot)> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_valid())
            // Safe: N <= u32::MAX in practice (capped at 256).
            .map(|(i, s)| (i as u32, s))
    }

    /// Finds a free slot, starting from `free_hint`.
    fn find_free_slot(&mut self) -> CapResult<usize> {
        for i in self.free_hint..N {
            if !self.slots[i].is_valid() {
                self.free_hint = i + 1;
                return Ok(i);
            }
        }
        for i in 0..self.free_hint {
            if !self.slots[i].is_valid() {
                self.free_hint = i + 1;
                return Ok(i);
            }
        }
        Err(CapError::TableFull)
    }
}

impl<const N: usize> Default for CapabilityTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_token(id: u64) -> CapToken {
        CapToken::new(id, CapType::Region, CapRights::READ.union(CapRights::WRITE), 0)
    }

    #[test]
    fn test_insert_and_lookup() {
        let mut table = CapabilityTable::<16>::new();
        let owner = PartitionId::new(1);
        let token = test_token(100);

        let (idx, gen) = table.insert_root(token, owner, 0).unwrap();
        assert_eq!(table.len(), 1);

        let slot = table.lookup(idx, gen).unwrap();
        assert_eq!(slot.token.id(), 100);
        assert_eq!(slot.depth, 0);
        assert_eq!(slot.parent_index, u32::MAX);
    }

    #[test]
    fn test_remove_and_stale() {
        let mut table = CapabilityTable::<16>::new();
        let owner = PartitionId::new(1);
        let token = test_token(200);

        let (idx, gen) = table.insert_root(token, owner, 0).unwrap();
        table.remove(idx, gen).unwrap();
        assert_eq!(table.len(), 0);
        assert!(table.lookup(idx, gen).is_err());
    }

    #[test]
    fn test_generation_counter() {
        let mut table = CapabilityTable::<16>::new();
        let owner = PartitionId::new(1);
        let token = test_token(300);

        let (idx, gen1) = table.insert_root(token, owner, 0).unwrap();
        table.remove(idx, gen1).unwrap();

        let (idx2, gen2) = table.insert_root(token, owner, 0).unwrap();
        assert_eq!(idx, idx2);
        assert_ne!(gen1, gen2);

        assert!(table.lookup(idx, gen1).is_err());
        assert!(table.lookup(idx2, gen2).is_ok());
    }

    #[test]
    fn test_table_full() {
        let mut table = CapabilityTable::<2>::new();
        let owner = PartitionId::new(1);
        let token = test_token(400);

        table.insert_root(token, owner, 0).unwrap();
        table.insert_root(token, owner, 0).unwrap();
        assert!(table.is_full());
        assert_eq!(table.insert_root(token, owner, 0), Err(CapError::TableFull));
    }

    #[test]
    fn test_insert_derived() {
        let mut table = CapabilityTable::<16>::new();
        let owner = PartitionId::new(1);
        let token = test_token(500);

        let (parent_idx, _) = table.insert_root(token, owner, 0).unwrap();
        let derived = CapToken::new(501, CapType::Region, CapRights::READ, 0);
        let (child_idx, child_gen) =
            table.insert_derived(derived, owner, 1, parent_idx, 42).unwrap();

        let slot = table.lookup(child_idx, child_gen).unwrap();
        assert_eq!(slot.depth, 1);
        assert_eq!(slot.parent_index, parent_idx);
        assert_eq!(slot.badge, 42);
    }

    #[test]
    fn test_iter_valid_entries() {
        let mut table = CapabilityTable::<16>::new();
        let owner = PartitionId::new(1);

        table.insert_root(test_token(1), owner, 0).unwrap();
        table.insert_root(test_token(2), owner, 0).unwrap();
        table.insert_root(test_token(3), owner, 0).unwrap();

        let count = table.iter().count();
        assert_eq!(count, 3);
    }
}
