//! Derivation tree for capability revocation propagation.
//!
//! When a capability is derived (via `grant`), a parent-child relationship
//! is established in this tree. Revoking a parent invalidates all derived
//! capabilities (children, grandchildren, etc.) via subtree walk.

use crate::error::{CapError, CapResult};
use crate::DEFAULT_CAP_TABLE_CAPACITY;

/// A node in the derivation tree.
///
/// Uses a first-child / next-sibling linked list layout for O(1)
/// insertion and efficient subtree traversal without allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivationNode {
    /// Whether this node is valid (not revoked).
    pub is_valid: bool,
    /// Depth in the derivation tree (0 = root).
    pub depth: u8,
    /// Epoch at which this capability was created.
    pub epoch: u64,
    /// Index of the first child (or `u32::MAX` if no children).
    pub first_child: u32,
    /// Index of the next sibling (or `u32::MAX` if no sibling).
    pub next_sibling: u32,
}

impl DerivationNode {
    /// An empty (unused) node.
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            is_valid: false,
            depth: 0,
            epoch: 0,
            first_child: u32::MAX,
            next_sibling: u32::MAX,
        }
    }

    /// A new root node at the given epoch.
    #[inline]
    #[must_use]
    pub const fn new_root(epoch: u64) -> Self {
        Self {
            is_valid: true,
            depth: 0,
            epoch,
            first_child: u32::MAX,
            next_sibling: u32::MAX,
        }
    }

    /// A new child node at the given depth and epoch.
    #[inline]
    #[must_use]
    pub const fn new_child(depth: u8, epoch: u64) -> Self {
        Self {
            is_valid: true,
            depth,
            epoch,
            first_child: u32::MAX,
            next_sibling: u32::MAX,
        }
    }

    /// Returns true if this node has children.
    #[inline]
    #[must_use]
    pub const fn has_children(&self) -> bool {
        self.first_child != u32::MAX
    }
}

impl Default for DerivationNode {
    fn default() -> Self {
        Self::empty()
    }
}

/// Derivation tree for tracking parent-child capability relationships.
///
/// Fixed-size array indexed by slot index. No heap allocation.
pub struct DerivationTree<const N: usize = DEFAULT_CAP_TABLE_CAPACITY> {
    /// Nodes indexed by capability slot index.
    nodes: [DerivationNode; N],
    /// Number of active (valid) nodes.
    count: usize,
}

impl<const N: usize> DerivationTree<N> {
    /// Creates a new empty derivation tree.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: [DerivationNode::empty(); N],
            count: 0,
        }
    }

    /// Returns the number of active nodes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the tree has no active nodes.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Registers a root capability in the tree.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::TreeFull`] if the index is out of bounds.
    pub fn add_root(&mut self, index: u32, epoch: u64) -> CapResult<()> {
        let idx = index as usize;
        if idx >= N {
            return Err(CapError::TreeFull);
        }
        self.nodes[idx] = DerivationNode::new_root(epoch);
        self.count += 1;
        Ok(())
    }

    /// Registers a derived capability in the tree, linking it to its parent.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::TreeFull`] if either index is out of bounds.
    /// Returns [`CapError::Revoked`] if the parent node has been revoked.
    pub fn add_child(
        &mut self,
        parent_index: u32,
        child_index: u32,
        depth: u8,
        epoch: u64,
    ) -> CapResult<()> {
        let pidx = parent_index as usize;
        let cidx = child_index as usize;

        if pidx >= N || cidx >= N {
            return Err(CapError::TreeFull);
        }
        if !self.nodes[pidx].is_valid {
            return Err(CapError::Revoked);
        }

        // Create child node and link to parent's child list (prepend).
        let mut child = DerivationNode::new_child(depth, epoch);
        child.next_sibling = self.nodes[pidx].first_child;
        self.nodes[pidx].first_child = child_index;
        self.nodes[cidx] = child;
        self.count += 1;

        Ok(())
    }

    /// Revokes a node and all its descendants. Returns the count of revoked nodes.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::InvalidHandle`] if the index is out of bounds.
    /// Returns [`CapError::Revoked`] if the node has already been revoked.
    pub fn revoke(&mut self, index: u32) -> CapResult<usize> {
        let idx = index as usize;
        if idx >= N {
            return Err(CapError::InvalidHandle);
        }
        if !self.nodes[idx].is_valid {
            return Err(CapError::Revoked);
        }
        Ok(self.revoke_subtree(index))
    }

    /// Returns the depth of the node at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`CapError::InvalidHandle`] if the index is invalid or the node is revoked.
    pub fn depth(&self, index: u32) -> CapResult<u8> {
        let idx = index as usize;
        if idx >= N || !self.nodes[idx].is_valid {
            return Err(CapError::InvalidHandle);
        }
        Ok(self.nodes[idx].depth)
    }

    /// Returns true if the node at the given index is valid.
    #[must_use]
    pub fn is_valid(&self, index: u32) -> bool {
        let idx = index as usize;
        idx < N && self.nodes[idx].is_valid
    }

    /// Returns a reference to a node by index.
    #[must_use]
    pub fn get(&self, index: u32) -> Option<&DerivationNode> {
        let idx = index as usize;
        if idx < N && self.nodes[idx].is_valid {
            Some(&self.nodes[idx])
        } else {
            None
        }
    }

    /// Collect all valid indices in the subtree rooted at `index`.
    ///
    /// Returns a fixed-size array of indices (up to N). This is used
    /// by revocation to synchronize the capability table.
    ///
    /// Uses an iterative stack to avoid stack overflow on wide trees.
    #[must_use]
    pub fn collect_subtree(&self, index: u32) -> [u32; N] {
        let mut result = [u32::MAX; N];
        let mut result_count = 0;
        let mut stack = [u32::MAX; N];
        let mut stack_top = 0;

        // Push the root.
        let idx = index as usize;
        if idx < N && self.nodes[idx].is_valid {
            stack[stack_top] = index;
            stack_top += 1;
        }

        while stack_top > 0 {
            stack_top -= 1;
            let current = stack[stack_top];
            let cidx = current as usize;
            if cidx >= N || !self.nodes[cidx].is_valid {
                continue;
            }

            if result_count < N {
                result[result_count] = current;
                result_count += 1;
            }

            // Push children.
            let mut child = self.nodes[cidx].first_child;
            while child != u32::MAX {
                let child_idx = child as usize;
                if child_idx >= N {
                    break;
                }
                if self.nodes[child_idx].is_valid && stack_top < N {
                    stack[stack_top] = child;
                    stack_top += 1;
                }
                child = self.nodes[child_idx].next_sibling;
            }
        }

        result
    }

    /// Iteratively revokes a subtree using an explicit stack.
    ///
    /// # Security
    ///
    /// The previous recursive implementation could overflow the stack on
    /// wide trees (e.g., 256 siblings under one parent). This iterative
    /// version uses a fixed-size stack bounded by N to prevent stack
    /// exhaustion denial-of-service.
    fn revoke_subtree(&mut self, index: u32) -> usize {
        let mut stack = [u32::MAX; N];
        let mut stack_top: usize = 0;
        let mut count: usize = 0;

        // Push the root of the subtree.
        let root_idx = index as usize;
        if root_idx >= N || !self.nodes[root_idx].is_valid {
            return 0;
        }
        stack[stack_top] = index;
        stack_top += 1;

        while stack_top > 0 {
            stack_top -= 1;
            let current = stack[stack_top];
            let cidx = current as usize;

            if cidx >= N || !self.nodes[cidx].is_valid {
                continue;
            }

            // Revoke this node.
            self.nodes[cidx].is_valid = false;
            self.count = self.count.saturating_sub(1);
            count += 1;

            // Push all children onto the stack.
            let mut child = self.nodes[cidx].first_child;
            while child != u32::MAX {
                let child_idx = child as usize;
                if child_idx >= N {
                    break;
                }
                if self.nodes[child_idx].is_valid && stack_top < N {
                    stack[stack_top] = child;
                    stack_top += 1;
                }
                // Read sibling BEFORE potentially invalidating the node.
                child = self.nodes[child_idx].next_sibling;
            }
        }

        count
    }
}

impl<const N: usize> Default for DerivationTree<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_root() {
        let mut tree = DerivationTree::<64>::new();
        tree.add_root(0, 1).unwrap();
        assert_eq!(tree.len(), 1);
        assert!(tree.is_valid(0));
        assert_eq!(tree.depth(0).unwrap(), 0);
    }

    #[test]
    fn test_add_child() {
        let mut tree = DerivationTree::<64>::new();
        tree.add_root(0, 1).unwrap();
        tree.add_child(0, 1, 1, 1).unwrap();
        assert_eq!(tree.len(), 2);
        assert!(tree.is_valid(1));
        assert_eq!(tree.depth(1).unwrap(), 1);
        assert!(tree.get(0).unwrap().has_children());
    }

    #[test]
    fn test_revoke_subtree() {
        let mut tree = DerivationTree::<64>::new();
        tree.add_root(0, 1).unwrap();
        tree.add_child(0, 1, 1, 1).unwrap();
        tree.add_child(0, 2, 1, 1).unwrap();
        tree.add_child(1, 3, 2, 1).unwrap();

        let revoked = tree.revoke(0).unwrap();
        assert_eq!(revoked, 4);
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn test_partial_revoke() {
        let mut tree = DerivationTree::<64>::new();
        tree.add_root(0, 1).unwrap();
        tree.add_child(0, 1, 1, 1).unwrap();
        tree.add_child(0, 2, 1, 1).unwrap();
        tree.add_child(1, 3, 2, 1).unwrap();

        let revoked = tree.revoke(1).unwrap();
        assert_eq!(revoked, 2);
        assert!(tree.is_valid(0));
        assert!(!tree.is_valid(1));
        assert!(tree.is_valid(2));
        assert!(!tree.is_valid(3));
    }

    #[test]
    fn test_add_child_to_revoked_parent() {
        let mut tree = DerivationTree::<64>::new();
        tree.add_root(0, 1).unwrap();
        tree.revoke(0).unwrap();
        assert_eq!(tree.add_child(0, 1, 1, 1), Err(CapError::Revoked));
    }

    #[test]
    fn test_out_of_bounds() {
        let mut tree = DerivationTree::<4>::new();
        assert_eq!(tree.add_root(10, 1), Err(CapError::TreeFull));
    }
}
