//! Coherence metric types for the RVM microhypervisor.
//!
//! Coherence is the first-class scheduling and resource-allocation signal
//! in RVM. Partitions with higher coherence scores receive preferential
//! scheduling and memory placement. Cut pressure drives migration and
//! split/merge decisions.
//!
//! See ADR-132 (DC-1, DC-2, DC-4, DC-9) for design constraints.

use crate::PartitionId;

/// A coherence score in the range `[0.0, 1.0]`.
///
/// Stored internally as a `u16` fixed-point value (0..=10000) to avoid
/// floating-point dependencies in `no_std` contexts. 1 basis point = 0.0001.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CoherenceScore(u16);

impl CoherenceScore {
    /// Maximum representable score (1.0).
    pub const MAX: Self = Self(10_000);

    /// Minimum representable score (0.0).
    pub const MIN: Self = Self(0);

    /// Default coherence threshold below which partitions are deprioritized.
    pub const DEFAULT_THRESHOLD: Self = Self(3_000); // 0.30

    /// Default merge threshold. Partitions must exceed this to merge (DC-11).
    pub const DEFAULT_MERGE_THRESHOLD: Self = Self(7_000); // 0.70

    /// Create a coherence score from a fixed-point value (0..=10000).
    ///
    /// Values above 10000 are clamped to 10000.
    #[must_use]
    pub const fn from_basis_points(bp: u16) -> Self {
        if bp > 10_000 {
            Self(10_000)
        } else {
            Self(bp)
        }
    }

    /// Return the raw basis-point value.
    #[must_use]
    pub const fn as_basis_points(self) -> u16 {
        self.0
    }

    /// Check whether this score meets the given threshold.
    #[must_use]
    pub const fn meets_threshold(self, threshold: Self) -> bool {
        self.0 >= threshold.0
    }

    /// Check whether this score is above the default coherence threshold.
    #[must_use]
    pub const fn is_coherent(self) -> bool {
        self.0 >= Self::DEFAULT_THRESHOLD.0
    }
}

/// An integrated-information (Phi) value used as a coherence input signal.
///
/// Stored as fixed-point with 4 decimal digits of precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhiValue(u32);

impl PhiValue {
    /// Zero Phi -- no integrated information.
    pub const ZERO: Self = Self(0);

    /// Create a Phi value from a fixed-point representation.
    #[must_use]
    pub const fn from_fixed(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw fixed-point value.
    #[must_use]
    pub const fn as_fixed(self) -> u32 {
        self.0
    }
}

/// Cut pressure: graph-derived isolation signal (ADR-132, DC-2).
///
/// High pressure triggers migration or split. Computed by the mincut crate
/// within the DC-2 time budget (50 microseconds per epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CutPressure(u32);

impl CutPressure {
    /// Zero pressure -- no migration or split needed.
    pub const ZERO: Self = Self(0);

    /// Default split threshold. Partitions exceeding this are candidates for split.
    pub const DEFAULT_SPLIT_THRESHOLD: Self = Self(8_000);

    /// Create a cut pressure value from a fixed-point representation.
    #[must_use]
    pub const fn from_fixed(val: u32) -> Self {
        Self(val)
    }

    /// Return the raw fixed-point value.
    #[must_use]
    pub const fn as_fixed(self) -> u32 {
        self.0
    }

    /// Check whether this pressure exceeds the given threshold.
    #[must_use]
    pub const fn exceeds_threshold(self, threshold: Self) -> bool {
        self.0 > threshold.0
    }
}

/// Unique identifier for a communication edge in the coherence graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct CommEdgeId(u64);

impl CommEdgeId {
    /// Create a new communication edge identifier.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw identifier value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// A weighted communication edge between two partitions.
///
/// Edges are the weighted links in the coherence graph. Weight represents
/// accumulated message bytes, decayed per epoch. The mincut algorithm
/// identifies the cheapest set of edges to sever for partition splitting.
#[derive(Debug, Clone, Copy)]
pub struct CommEdge {
    /// Unique identifier for this edge.
    pub id: CommEdgeId,
    /// Source partition.
    pub source: PartitionId,
    /// Destination partition.
    pub dest: PartitionId,
    /// Edge weight (accumulated message bytes, decayed per epoch).
    pub weight: u64,
    /// Epoch in which this edge was last updated.
    pub last_epoch: u32,
}
