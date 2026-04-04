//! Fixed-size coherence graph for partition communication topology.
//!
//! `CoherenceGraph` stores partition nodes and weighted edges in a
//! fixed-capacity adjacency structure with zero heap allocation,
//! suitable for `no_std` microhypervisor use.

use rvm_types::PartitionId;

/// Index into the node array.
pub type NodeIdx = u16;

/// Index into the edge array.
pub type EdgeIdx = u16;

/// Sentinel value indicating an unused slot.
const INVALID: u16 = u16::MAX;

/// A node in the coherence graph, representing a partition.
#[derive(Debug, Clone, Copy)]
struct Node {
    /// The partition this node represents, or `None` if the slot is free.
    partition: Option<PartitionId>,
    /// Index of the first outgoing edge in the edge array (linked list head).
    first_edge: u16,
}

impl Node {
    const EMPTY: Self = Self {
        partition: None,
        first_edge: INVALID,
    };
}

/// A directed weighted edge in the coherence graph.
#[derive(Debug, Clone, Copy)]
struct Edge {
    /// Source node index.
    from: NodeIdx,
    /// Destination node index.
    to: NodeIdx,
    /// Edge weight (communication volume, decayed per epoch).
    weight: u64,
    /// Next edge in the adjacency list for the `from` node.
    next_from: u16,
    /// Whether this slot is in use.
    active: bool,
}

impl Edge {
    const EMPTY: Self = Self {
        from: 0,
        to: 0,
        weight: 0,
        next_from: INVALID,
        active: false,
    };
}

/// Result type for graph operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphError {
    /// No free node slots available.
    NodeCapacityExhausted,
    /// No free edge slots available.
    EdgeCapacityExhausted,
    /// The specified node was not found.
    NodeNotFound,
    /// The specified edge was not found.
    EdgeNotFound,
    /// A node for this partition already exists.
    DuplicateNode,
}

/// Fixed-size coherence graph.
///
/// `MAX_NODES` bounds the number of partition nodes, and `MAX_EDGES`
/// bounds the number of directed communication edges. Both are
/// compile-time constants to enable fully stack-allocated operation.
pub struct CoherenceGraph<const MAX_NODES: usize, const MAX_EDGES: usize> {
    nodes: [Node; MAX_NODES],
    edges: [Edge; MAX_EDGES],
    node_count: u16,
    edge_count: u16,
}

impl<const MAX_NODES: usize, const MAX_EDGES: usize> CoherenceGraph<MAX_NODES, MAX_EDGES> {
    /// Create a new empty coherence graph.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            nodes: [Node::EMPTY; MAX_NODES],
            edges: [Edge::EMPTY; MAX_EDGES],
            node_count: 0,
            edge_count: 0,
        }
    }

    /// Number of active nodes.
    #[must_use]
    pub const fn node_count(&self) -> u16 {
        self.node_count
    }

    /// Number of active edges.
    #[must_use]
    pub const fn edge_count(&self) -> u16 {
        self.edge_count
    }

    /// Add a partition node to the graph. Returns the node index.
    pub fn add_node(&mut self, partition_id: PartitionId) -> Result<NodeIdx, GraphError> {
        // Check for duplicate
        if self.find_node(partition_id).is_some() {
            return Err(GraphError::DuplicateNode);
        }

        // Find a free slot
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if node.partition.is_none() {
                node.partition = Some(partition_id);
                node.first_edge = INVALID;
                self.node_count += 1;
                return Ok(i as NodeIdx);
            }
        }
        Err(GraphError::NodeCapacityExhausted)
    }

    /// Remove a partition node and all its incident edges.
    pub fn remove_node(&mut self, partition_id: PartitionId) -> Result<(), GraphError> {
        let idx = self.find_node(partition_id).ok_or(GraphError::NodeNotFound)?;

        // Remove all edges where this node is source or destination
        for i in 0..MAX_EDGES {
            if self.edges[i].active
                && (self.edges[i].from == idx || self.edges[i].to == idx)
            {
                self.remove_edge_by_index(i as EdgeIdx);
            }
        }

        self.nodes[idx as usize].partition = None;
        self.nodes[idx as usize].first_edge = INVALID;
        self.node_count = self.node_count.saturating_sub(1);
        Ok(())
    }

    /// Add a directed weighted edge from one node to another. Returns the edge index.
    pub fn add_edge(
        &mut self,
        from: PartitionId,
        to: PartitionId,
        weight: u64,
    ) -> Result<EdgeIdx, GraphError> {
        let from_idx = self.find_node(from).ok_or(GraphError::NodeNotFound)?;
        let to_idx = self.find_node(to).ok_or(GraphError::NodeNotFound)?;

        // Find a free edge slot
        let edge_idx = self.alloc_edge()?;

        let old_head = self.nodes[from_idx as usize].first_edge;
        self.edges[edge_idx as usize] = Edge {
            from: from_idx,
            to: to_idx,
            weight,
            next_from: old_head,
            active: true,
        };
        self.nodes[from_idx as usize].first_edge = edge_idx;
        self.edge_count += 1;

        Ok(edge_idx)
    }

    /// Update the weight of an edge by adding `delta` (saturating).
    pub fn update_weight(&mut self, edge_id: EdgeIdx, delta: i64) -> Result<(), GraphError> {
        let idx = edge_id as usize;
        if idx >= MAX_EDGES || !self.edges[idx].active {
            return Err(GraphError::EdgeNotFound);
        }
        if delta >= 0 {
            self.edges[idx].weight = self.edges[idx].weight.saturating_add(delta as u64);
        } else {
            self.edges[idx].weight = self.edges[idx]
                .weight
                .saturating_sub(delta.unsigned_abs());
        }
        Ok(())
    }

    /// Get the weight of an edge by index.
    #[must_use]
    pub fn edge_weight(&self, edge_id: EdgeIdx) -> Option<u64> {
        let idx = edge_id as usize;
        if idx < MAX_EDGES && self.edges[idx].active {
            Some(self.edges[idx].weight)
        } else {
            None
        }
    }

    /// Get the source and destination partition IDs for an edge.
    #[must_use]
    pub fn edge_endpoints(&self, edge_id: EdgeIdx) -> Option<(PartitionId, PartitionId)> {
        let idx = edge_id as usize;
        if idx >= MAX_EDGES || !self.edges[idx].active {
            return None;
        }
        let from_pid = self.nodes[self.edges[idx].from as usize].partition?;
        let to_pid = self.nodes[self.edges[idx].to as usize].partition?;
        Some((from_pid, to_pid))
    }

    /// Iterate over neighbor node indices of a given partition.
    ///
    /// Returns `(neighbor_node_idx, edge_weight)` pairs for all outgoing
    /// edges from the given partition.
    pub fn neighbors(
        &self,
        partition_id: PartitionId,
    ) -> Option<NeighborIter<'_, MAX_NODES, MAX_EDGES>> {
        let idx = self.find_node(partition_id)?;
        Some(NeighborIter {
            graph: self,
            current_edge: self.nodes[idx as usize].first_edge,
        })
    }

    /// Sum of all incident edge weights for a partition (outgoing edges).
    #[must_use]
    pub fn total_weight(&self, partition_id: PartitionId) -> u64 {
        let mut sum = 0u64;
        // Outgoing edges
        if let Some(iter) = self.neighbors(partition_id) {
            for (_, w) in iter {
                sum = sum.saturating_add(w);
            }
        }
        // Incoming edges
        if let Some(idx) = self.find_node(partition_id) {
            for i in 0..MAX_EDGES {
                if self.edges[i].active && self.edges[i].to == idx {
                    sum = sum.saturating_add(self.edges[i].weight);
                }
            }
        }
        sum
    }

    /// Sum of internal edge weights (edges where both endpoints are the
    /// given partition or edges between two specific partitions).
    ///
    /// For coherence scoring, "internal" edges are those where both
    /// endpoints belong to the same logical group. In the single-partition
    /// case, this is self-loops. For multi-partition queries, callers
    /// should use `edge_weight_between`.
    #[must_use]
    pub fn internal_weight(&self, partition_id: PartitionId) -> u64 {
        let idx = match self.find_node(partition_id) {
            Some(i) => i,
            None => return 0,
        };
        let mut sum = 0u64;
        for i in 0..MAX_EDGES {
            if self.edges[i].active
                && self.edges[i].from == idx
                && self.edges[i].to == idx
            {
                sum = sum.saturating_add(self.edges[i].weight);
            }
        }
        sum
    }

    /// Sum of edge weights between two specific partitions (in either direction).
    #[must_use]
    pub fn edge_weight_between(&self, a: PartitionId, b: PartitionId) -> u64 {
        let a_idx = match self.find_node(a) {
            Some(i) => i,
            None => return 0,
        };
        let b_idx = match self.find_node(b) {
            Some(i) => i,
            None => return 0,
        };
        let mut sum = 0u64;
        for i in 0..MAX_EDGES {
            if self.edges[i].active {
                let (f, t) = (self.edges[i].from, self.edges[i].to);
                if (f == a_idx && t == b_idx) || (f == b_idx && t == a_idx) {
                    sum = sum.saturating_add(self.edges[i].weight);
                }
            }
        }
        sum
    }

    /// Get the node index for a partition, or `None` if not present.
    #[must_use]
    pub fn find_node(&self, partition_id: PartitionId) -> Option<NodeIdx> {
        for (i, node) in self.nodes.iter().enumerate() {
            if node.partition == Some(partition_id) {
                return Some(i as NodeIdx);
            }
        }
        None
    }

    /// Get the partition ID for a node index.
    #[must_use]
    pub fn partition_at(&self, idx: NodeIdx) -> Option<PartitionId> {
        if (idx as usize) < MAX_NODES {
            self.nodes[idx as usize].partition
        } else {
            None
        }
    }

    /// Iterate over all active node indices and their partition IDs.
    pub fn active_nodes(&self) -> impl Iterator<Item = (NodeIdx, PartitionId)> + '_ {
        self.nodes
            .iter()
            .enumerate()
            .filter_map(|(i, n)| n.partition.map(|pid| (i as NodeIdx, pid)))
    }

    /// Iterate over all active edges as `(edge_idx, from_node, to_node, weight)`.
    pub fn active_edges(&self) -> impl Iterator<Item = (EdgeIdx, NodeIdx, NodeIdx, u64)> + '_ {
        self.edges
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                if e.active {
                    Some((i as EdgeIdx, e.from, e.to, e.weight))
                } else {
                    None
                }
            })
    }

    /// Allocate a free edge slot.
    fn alloc_edge(&self) -> Result<EdgeIdx, GraphError> {
        for (i, e) in self.edges.iter().enumerate() {
            if !e.active {
                return Ok(i as EdgeIdx);
            }
        }
        Err(GraphError::EdgeCapacityExhausted)
    }

    /// Remove an edge by its index, repairing the adjacency linked list.
    fn remove_edge_by_index(&mut self, edge_idx: EdgeIdx) {
        let idx = edge_idx as usize;
        if idx >= MAX_EDGES || !self.edges[idx].active {
            return;
        }

        let from_node = self.edges[idx].from as usize;

        // Repair the linked list: remove this edge from the from-node's list
        if self.nodes[from_node].first_edge == edge_idx {
            self.nodes[from_node].first_edge = self.edges[idx].next_from;
        } else {
            // Walk the list to find the predecessor
            let mut cur = self.nodes[from_node].first_edge;
            while cur != INVALID {
                let cur_idx = cur as usize;
                if self.edges[cur_idx].next_from == edge_idx {
                    self.edges[cur_idx].next_from = self.edges[idx].next_from;
                    break;
                }
                cur = self.edges[cur_idx].next_from;
            }
        }

        self.edges[idx].active = false;
        self.edge_count = self.edge_count.saturating_sub(1);
    }
}

/// Iterator over the neighbors of a node.
pub struct NeighborIter<'a, const MAX_NODES: usize, const MAX_EDGES: usize> {
    graph: &'a CoherenceGraph<MAX_NODES, MAX_EDGES>,
    current_edge: u16,
}

impl<const MAX_NODES: usize, const MAX_EDGES: usize> Iterator
    for NeighborIter<'_, MAX_NODES, MAX_EDGES>
{
    /// `(neighbor_node_idx, edge_weight)`
    type Item = (NodeIdx, u64);

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_edge != INVALID {
            let idx = self.current_edge as usize;
            if idx >= MAX_EDGES {
                break;
            }
            let edge = &self.graph.edges[idx];
            self.current_edge = edge.next_from;
            if edge.active {
                return Some((edge.to, edge.weight));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(n: u32) -> PartitionId {
        PartitionId::new(n)
    }

    #[test]
    fn add_and_find_nodes() {
        let mut g = CoherenceGraph::<8, 16>::new();
        let n0 = g.add_node(pid(1)).unwrap();
        let n1 = g.add_node(pid(2)).unwrap();
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.find_node(pid(1)), Some(n0));
        assert_eq!(g.find_node(pid(2)), Some(n1));
        assert_eq!(g.find_node(pid(99)), None);
    }

    #[test]
    fn duplicate_node_rejected() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        assert_eq!(g.add_node(pid(1)), Err(GraphError::DuplicateNode));
    }

    #[test]
    fn node_capacity_exhausted() {
        let mut g = CoherenceGraph::<2, 4>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        assert_eq!(g.add_node(pid(3)), Err(GraphError::NodeCapacityExhausted));
    }

    #[test]
    fn add_edge_and_query_weight() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        let e = g.add_edge(pid(1), pid(2), 100).unwrap();
        assert_eq!(g.edge_weight(e), Some(100));
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn update_weight_positive_and_negative() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        let e = g.add_edge(pid(1), pid(2), 100).unwrap();

        g.update_weight(e, 50).unwrap();
        assert_eq!(g.edge_weight(e), Some(150));

        g.update_weight(e, -200).unwrap();
        assert_eq!(g.edge_weight(e), Some(0)); // saturating
    }

    #[test]
    fn neighbors_iteration() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_node(pid(3)).unwrap();
        g.add_edge(pid(1), pid(2), 10).unwrap();
        g.add_edge(pid(1), pid(3), 20).unwrap();

        let mut count = 0u32;
        let mut total = 0u64;
        for (_idx, w) in g.neighbors(pid(1)).unwrap() {
            count += 1;
            total += w;
        }
        assert_eq!(count, 2);
        assert_eq!(total, 30);
    }

    #[test]
    fn total_weight_includes_incoming_and_outgoing() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 100).unwrap();
        g.add_edge(pid(2), pid(1), 50).unwrap();

        // pid(1): outgoing 100 + incoming 50
        assert_eq!(g.total_weight(pid(1)), 150);
    }

    #[test]
    fn remove_node_clears_edges() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 100).unwrap();
        g.add_edge(pid(2), pid(1), 50).unwrap();
        assert_eq!(g.edge_count(), 2);

        g.remove_node(pid(1)).unwrap();
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.edge_count(), 0);
        assert_eq!(g.find_node(pid(1)), None);
    }

    #[test]
    fn edge_weight_between_bidirectional() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        g.add_edge(pid(1), pid(2), 100).unwrap();
        g.add_edge(pid(2), pid(1), 50).unwrap();
        assert_eq!(g.edge_weight_between(pid(1), pid(2)), 150);
        assert_eq!(g.edge_weight_between(pid(2), pid(1)), 150);
    }

    #[test]
    fn edge_endpoints_retrieval() {
        let mut g = CoherenceGraph::<8, 16>::new();
        g.add_node(pid(1)).unwrap();
        g.add_node(pid(2)).unwrap();
        let e = g.add_edge(pid(1), pid(2), 42).unwrap();
        assert_eq!(g.edge_endpoints(e), Some((pid(1), pid(2))));
    }
}
