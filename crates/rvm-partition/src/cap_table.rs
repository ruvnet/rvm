//! Per-partition capability table.

use rvm_types::{CapToken, RvmError, RvmResult};

/// Maximum capabilities per partition.
pub const MAX_CAPS_PER_PARTITION: usize = 256;

/// A fixed-size capability table scoped to a single partition.
#[derive(Debug)]
pub struct CapabilityTable {
    entries: [Option<CapToken>; MAX_CAPS_PER_PARTITION],
    count: usize,
}

impl CapabilityTable {
    /// Create an empty capability table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: [None; MAX_CAPS_PER_PARTITION],
            count: 0,
        }
    }

    /// Insert a capability into the table. Returns the slot index.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the table is full.
    pub fn insert(&mut self, token: CapToken) -> RvmResult<usize> {
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(token);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(RvmError::ResourceLimitExceeded)
    }

    /// Look up a capability by slot index.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&CapToken> {
        self.entries.get(index).and_then(|e| e.as_ref())
    }

    /// Remove a capability by slot index.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::InsufficientCapability`] if the slot is empty or out of bounds.
    ///
    /// # Panics
    ///
    /// Cannot panic: the `unwrap` is guarded by the `Some(_)` pattern match.
    pub fn remove(&mut self, index: usize) -> RvmResult<CapToken> {
        match self.entries.get_mut(index) {
            Some(slot @ Some(_)) => {
                let token = slot.take().unwrap();
                self.count -= 1;
                Ok(token)
            }
            _ => Err(RvmError::InsufficientCapability),
        }
    }

    /// Return the number of capabilities in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for CapabilityTable {
    fn default() -> Self {
        Self::new()
    }
}
