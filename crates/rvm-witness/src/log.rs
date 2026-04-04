//! Append-only ring buffer witness log (ADR-134).
//!
//! Thread-safe via `spin::Mutex`. Designed for < 500 ns emission.

use crate::hash::compute_chain_hash;
use rvm_types::WitnessRecord;
use spin::Mutex;

/// Append-only ring buffer of witness records.
pub struct WitnessLog<const N: usize> {
    inner: Mutex<WitnessLogInner<N>>,
}

struct WitnessLogInner<const N: usize> {
    records: [WitnessRecord; N],
    write_pos: usize,
    chain_hash: u64,
    sequence: u64,
    total_emitted: u64,
}

impl<const N: usize> WitnessLog<N> {
    /// Creates a new empty witness log.
    ///
    /// # Panics
    ///
    /// Panics if `N` is zero.
    #[must_use]
    pub fn new() -> Self {
        assert!(N > 0, "witness log capacity must be > 0");
        Self {
            inner: Mutex::new(WitnessLogInner {
                records: [WitnessRecord::zeroed(); N],
                write_pos: 0,
                chain_hash: 0,
                sequence: 0,
                total_emitted: 0,
            }),
        }
    }

    /// Appends a pre-built witness record to the log.
    ///
    /// Fills `sequence`, `prev_hash`, and `record_hash`. Returns the
    /// sequence number.
    #[allow(clippy::cast_possible_truncation)]
    pub fn append(&self, mut record: WitnessRecord) -> u64 {
        let mut inner = self.inner.lock();
        let seq = inner.sequence;
        let prev_hash = inner.chain_hash;

        record.sequence = seq;
        record.prev_hash = prev_hash as u32;

        let chain = compute_chain_hash(prev_hash, seq);
        record.record_hash = chain as u32;

        let pos = inner.write_pos;
        inner.records[pos] = record;
        inner.write_pos = (pos + 1) % N;
        inner.chain_hash = chain;
        inner.sequence = seq + 1;
        inner.total_emitted += 1;

        seq
    }

    /// Returns the total number of records ever emitted.
    pub fn total_emitted(&self) -> u64 {
        self.inner.lock().total_emitted
    }

    /// Returns the number of records currently in the buffer.
    #[allow(clippy::cast_possible_truncation)]
    pub fn len(&self) -> usize {
        let total = self.inner.lock().total_emitted;
        // Safe: if total < N then total fits in usize since N is usize.
        if total >= N as u64 { N } else { total as usize }
    }

    /// Returns true if no records have been emitted.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().total_emitted == 0
    }

    /// Returns a copy of the record at the given ring index.
    pub fn get(&self, ring_index: usize) -> Option<WitnessRecord> {
        if ring_index >= N {
            return None;
        }
        let inner = self.inner.lock();
        if inner.total_emitted == 0 {
            return None;
        }
        Some(inner.records[ring_index])
    }

    /// Copies the most recent records into the buffer. Returns count copied.
    pub fn snapshot(&self, buf: &mut [WitnessRecord]) -> usize {
        let inner = self.inner.lock();
        #[allow(clippy::cast_possible_truncation)]
        let available = if inner.total_emitted >= N as u64 {
            N
        } else {
            // Safe: total_emitted < N and N is usize, so it fits.
            inner.total_emitted as usize
        };
        let to_copy = buf.len().min(available);
        if to_copy == 0 {
            return 0;
        }
        let start = if inner.total_emitted >= N as u64 {
            inner.write_pos
        } else {
            0
        };
        for (i, slot) in buf.iter_mut().enumerate().take(to_copy) {
            let idx = (start + (available - to_copy) + i) % N;
            *slot = inner.records[idx];
        }
        to_copy
    }
}

impl<const N: usize> Default for WitnessLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_types::ActionKind;

    fn make_record(kind: ActionKind, actor: u32, target: u64, ts: u64) -> WitnessRecord {
        let mut r = WitnessRecord::zeroed();
        r.action_kind = kind as u8;
        r.actor_partition_id = actor;
        r.target_object_id = target;
        r.timestamp_ns = ts;
        r
    }

    #[test]
    fn test_append_and_sequence() {
        let log = WitnessLog::<16>::new();
        let s0 = log.append(make_record(ActionKind::PartitionCreate, 1, 100, 1000));
        let s1 = log.append(make_record(ActionKind::CapabilityGrant, 1, 200, 2000));
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
        assert_eq!(log.total_emitted(), 2);
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn test_ring_wrap() {
        let log = WitnessLog::<4>::new();
        for i in 0..10u64 {
            log.append(make_record(ActionKind::SchedulerEpoch, 1, i, i * 100));
        }
        assert_eq!(log.total_emitted(), 10);
        assert_eq!(log.len(), 4);
    }

    #[test]
    fn test_hash_chain() {
        let log = WitnessLog::<16>::new();
        log.append(make_record(ActionKind::PartitionCreate, 1, 10, 100));
        log.append(make_record(ActionKind::CapabilityGrant, 1, 20, 200));

        let r0 = log.get(0).unwrap();
        let r1 = log.get(1).unwrap();
        assert_eq!(r0.prev_hash, 0);
        assert_ne!(r1.prev_hash, 0);
    }

    #[test]
    fn test_snapshot() {
        let log = WitnessLog::<16>::new();
        for i in 0..5u64 {
            log.append(make_record(ActionKind::SchedulerEpoch, 1, i, i * 100));
        }
        let mut buf = [WitnessRecord::zeroed(); 3];
        let copied = log.snapshot(&mut buf);
        assert_eq!(copied, 3);
        assert_eq!(buf[0].sequence, 2);
        assert_eq!(buf[1].sequence, 3);
        assert_eq!(buf[2].sequence, 4);
    }

    #[test]
    fn test_empty_log() {
        let log = WitnessLog::<16>::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }
}
