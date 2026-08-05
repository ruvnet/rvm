//! Signed size limits, enforced at parse time.
//!
//! ADR-284 §1.8 requires maximum model, runtime, memory, and state sizes to
//! be enforced through *signed policy*. ADR-287 §1 says why: the limit that
//! used to exist was a compile-time constant, so a publisher could neither
//! raise it for a real agent runtime nor could an operator tighten it for a
//! constrained deployment. A constant is a wall in a fixed place; a policy is
//! a wall the signer chooses.
//!
//! # Relationship to `rvm-wasm`'s 1 MiB cap
//!
//! `rvm_wasm::MAX_MODULE_SIZE` (1 MiB) still exists and still applies. It is
//! the *executor-side backstop*: the last check before a module is handed to
//! the interpreter, unconditional and independent of any policy input. This
//! crate's [`SizePolicy`] gates strictly earlier — at container parse time,
//! before a segment is ever a candidate for loading — and can only be as
//! permissive as the executor will subsequently allow. Raising
//! [`SizePolicy::max_runtime_bytes`] above 1 MiB does not raise the executor
//! cap; ADR-287's streaming-validation work in `rvm-wasm` is what removes it.
//! Until then a runtime segment over 1 MiB passes policy and is refused by
//! the executor, which is the fail-closed ordering.
//!
//! # Fail-closed defaults
//!
//! [`SizePolicy::default`] is conservative on every axis (ADR-287 §1.3):
//! when policy omits a limit the runtime applies a restrictive default, and
//! an artifact that needs more says so in signed policy.

use crate::container::ParsedSegment;
use crate::format::SegmentClass;

/// Maximum total bytes permitted per segment class, plus container-wide caps.
///
/// Limits are on the *sum* of each class rather than on individual segments,
/// which is what makes them a real resource envelope: an artifact cannot slip
/// past a per-segment limit by splitting one oversize payload into twenty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizePolicy {
    /// Total bytes of executable payload: kernel, eBPF, WASM.
    pub max_runtime_bytes: u64,
    /// Total bytes of model payload: vectors, indexes, codebooks, hot data.
    pub max_model_bytes: u64,
    /// Total bytes of mutable state: journals, deltas, COW maps, refcounts.
    pub max_state_bytes: u64,
    /// Total bytes of everything else: manifests, metadata, witnesses.
    pub max_memory_bytes: u64,
    /// Total container size, header bytes and padding included.
    pub max_container_bytes: u64,
    /// Maximum number of segments in the container.
    pub max_segments: usize,
}

impl SizePolicy {
    /// The fail-closed default: tight enough that an artifact needing more
    /// has to say so in signed policy.
    pub const FAIL_CLOSED: Self = Self {
        max_runtime_bytes: 1024 * 1024,
        max_model_bytes: 64 * 1024 * 1024,
        max_state_bytes: 16 * 1024 * 1024,
        max_memory_bytes: 4 * 1024 * 1024,
        max_container_bytes: 128 * 1024 * 1024,
        max_segments: 4096,
    };

    /// A policy that permits anything the *format* permits.
    ///
    /// Provided for tests and for callers that enforce their limits
    /// elsewhere. It is not a default and never becomes one.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            max_runtime_bytes: u64::MAX,
            max_model_bytes: u64::MAX,
            max_state_bytes: u64::MAX,
            max_memory_bytes: u64::MAX,
            max_container_bytes: u64::MAX,
            max_segments: crate::format::MAX_SEGMENTS,
        }
    }

    /// This policy with a different runtime budget.
    #[must_use]
    pub const fn with_max_runtime_bytes(mut self, bytes: u64) -> Self {
        self.max_runtime_bytes = bytes;
        self
    }

    /// This policy with a different model budget.
    #[must_use]
    pub const fn with_max_model_bytes(mut self, bytes: u64) -> Self {
        self.max_model_bytes = bytes;
        self
    }

    /// The budget governing `class`.
    #[must_use]
    pub const fn budget_for(&self, class: SegmentClass) -> u64 {
        match class {
            SegmentClass::Runtime => self.max_runtime_bytes,
            SegmentClass::Model => self.max_model_bytes,
            SegmentClass::State => self.max_state_bytes,
            SegmentClass::Memory => self.max_memory_bytes,
        }
    }
}

impl Default for SizePolicy {
    fn default() -> Self {
        Self::FAIL_CLOSED
    }
}

/// Which limit an artifact exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeViolation {
    /// A segment class ran over its byte budget.
    ClassBudget {
        /// The class whose budget was exceeded.
        class: SegmentClass,
        /// Bytes the container declares for that class.
        declared: u64,
        /// Bytes policy permits.
        limit: u64,
    },
    /// The container is larger than policy permits.
    ContainerBytes {
        /// Container size in bytes.
        declared: u64,
        /// Bytes policy permits.
        limit: u64,
    },
    /// The container holds more segments than policy permits.
    SegmentCount {
        /// Segments the container holds.
        declared: usize,
        /// Segments policy permits.
        limit: usize,
    },
}

/// The bytes a container declares in each size class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SizeTally {
    /// Total executable payload bytes.
    pub runtime_bytes: u64,
    /// Total model payload bytes.
    pub model_bytes: u64,
    /// Total mutable-state payload bytes.
    pub state_bytes: u64,
    /// Total metadata payload bytes.
    pub memory_bytes: u64,
}

impl SizeTally {
    /// The bytes charged to `class`.
    #[must_use]
    pub const fn bytes_for(&self, class: SegmentClass) -> u64 {
        match class {
            SegmentClass::Runtime => self.runtime_bytes,
            SegmentClass::Model => self.model_bytes,
            SegmentClass::State => self.state_bytes,
            SegmentClass::Memory => self.memory_bytes,
        }
    }
}

/// Sum the payload bytes each segment class declares.
///
/// Sums saturate rather than wrapping, so a container that overflows the
/// counter reads as "over every budget" instead of as "under".
#[must_use]
pub fn tally(segments: &[ParsedSegment]) -> SizeTally {
    let mut t = SizeTally::default();
    for seg in segments {
        let len = seg.header.payload_length;
        match seg.header.class() {
            SegmentClass::Runtime => t.runtime_bytes = t.runtime_bytes.saturating_add(len),
            SegmentClass::Model => t.model_bytes = t.model_bytes.saturating_add(len),
            SegmentClass::State => t.state_bytes = t.state_bytes.saturating_add(len),
            SegmentClass::Memory => t.memory_bytes = t.memory_bytes.saturating_add(len),
        }
    }
    t
}

/// Check a walked container against `policy`.
///
/// Returns every violation rather than the first, so one report can carry the
/// whole picture instead of the caller re-running after each fix.
#[must_use]
pub fn check(
    container_bytes: u64,
    segments: &[ParsedSegment],
    policy: &SizePolicy,
) -> alloc::vec::Vec<SizeViolation> {
    let mut out = alloc::vec::Vec::new();

    if container_bytes > policy.max_container_bytes {
        out.push(SizeViolation::ContainerBytes {
            declared: container_bytes,
            limit: policy.max_container_bytes,
        });
    }
    if segments.len() > policy.max_segments {
        out.push(SizeViolation::SegmentCount {
            declared: segments.len(),
            limit: policy.max_segments,
        });
    }

    let tally = tally(segments);
    for class in [
        SegmentClass::Runtime,
        SegmentClass::Model,
        SegmentClass::State,
        SegmentClass::Memory,
    ] {
        let declared = tally.bytes_for(class);
        let limit = policy.budget_for(class);
        if declared > limit {
            out.push(SizeViolation::ClassBudget {
                class,
                declared,
                limit,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::walk;
    use crate::format::{SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
    use crate::testkit;

    fn container_with_wasm(payload_len: usize) -> alloc::vec::Vec<u8> {
        let payload = alloc::vec![0x00u8; payload_len];
        let mut data = testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"root", 1);
        data.extend(testkit::unsigned_segment(SEG_TYPE_WASM, &payload, 2));
        data
    }

    #[test]
    fn the_default_policy_is_the_fail_closed_one() {
        assert_eq!(SizePolicy::default(), SizePolicy::FAIL_CLOSED);
        assert_eq!(SizePolicy::default().max_runtime_bytes, 1024 * 1024);
    }

    #[test]
    fn a_container_inside_every_budget_reports_no_violation() {
        let data = container_with_wasm(2048);
        let segs = walk(&data).unwrap();
        assert!(check(data.len() as u64, &segs, &SizePolicy::default()).is_empty());
    }

    #[test]
    fn an_oversize_runtime_segment_is_reported_against_its_budget() {
        let data = container_with_wasm(4096);
        let segs = walk(&data).unwrap();
        let policy = SizePolicy::default().with_max_runtime_bytes(1024);

        let violations = check(data.len() as u64, &segs, &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0],
            SizeViolation::ClassBudget {
                class: SegmentClass::Runtime,
                declared: 4096,
                limit: 1024,
            }
        );
    }

    #[test]
    fn budgets_are_summed_so_splitting_a_payload_does_not_evade_them() {
        let payload = alloc::vec![0u8; 1024];
        let mut data = testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"root", 1);
        for id in 2..=4 {
            data.extend(testkit::unsigned_segment(SEG_TYPE_WASM, &payload, id));
        }
        let segs = walk(&data).unwrap();
        let policy = SizePolicy::default().with_max_runtime_bytes(2048);

        let violations = check(data.len() as u64, &segs, &policy);
        assert_eq!(
            violations,
            alloc::vec![SizeViolation::ClassBudget {
                class: SegmentClass::Runtime,
                declared: 3072,
                limit: 2048,
            }]
        );
    }

    #[test]
    fn every_violation_is_reported_not_just_the_first() {
        let data = container_with_wasm(4096);
        let segs = walk(&data).unwrap();
        let policy = SizePolicy {
            max_container_bytes: 16,
            max_segments: 1,
            ..SizePolicy::default().with_max_runtime_bytes(8)
        };
        assert_eq!(check(data.len() as u64, &segs, &policy).len(), 3);
    }

    #[test]
    fn segments_are_tallied_into_the_right_classes() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"root", 1);
        data.extend(testkit::unsigned_segment(SEG_TYPE_WASM, b"code", 2));
        data.extend(testkit::unsigned_segment(0x01, b"vectors!", 3));
        data.extend(testkit::unsigned_segment(SEG_TYPE_META, b"meta", 4));

        let segs = walk(&data).unwrap();
        let t = tally(&segs);
        assert_eq!(t.runtime_bytes, 4);
        assert_eq!(t.model_bytes, 8);
        assert_eq!(t.state_bytes, 0);
        // "root" plus "meta".
        assert_eq!(t.memory_bytes, 8);
    }

    #[test]
    fn the_permissive_policy_admits_what_the_format_admits() {
        let data = container_with_wasm(4096);
        let segs = walk(&data).unwrap();
        assert!(check(data.len() as u64, &segs, &SizePolicy::permissive()).is_empty());
    }

    #[test]
    fn the_default_runtime_budget_matches_the_executor_backstop() {
        // rvm_wasm::MAX_MODULE_SIZE is 1 MiB and applies unconditionally at
        // load time. The fail-closed policy default deliberately does not
        // start out more permissive than the executor will accept.
        assert_eq!(SizePolicy::FAIL_CLOSED.max_runtime_bytes, 1024 * 1024);
    }
}
