//! Append-only ring buffer witness log (ADR-134).
//!
//! Thread-safe via `spin::Mutex`. Designed for < 500 ns emission.

use crate::hash::compute_chain_hash;
use rvm_types::WitnessRecord;
use spin::Mutex;

/// XOR-fold a 64-bit hash into 32 bits.
///
/// This preserves entropy from both halves of the hash, unlike simple
/// truncation (`as u32`) which discards the upper 32 bits entirely.
///
/// `fold(h) = (h >> 32) ^ (h & 0xFFFF_FFFF)`
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn fold_u64_to_u32(h: u64) -> u32 {
    ((h >> 32) ^ h) as u32
}

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

/// An atomic boundary in a witness log.
///
/// The sequence is the next record that will be written. The full internal
/// chain hash is retained so a later epoch can be verified without pretending
/// it began at genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessCheckpoint {
    next_sequence: u64,
    chain_hash: u64,
}

/// Complete result of an atomic checkpoint-relative snapshot.
///
/// `end_checkpoint` was captured under the same lock as the copied range, so
/// it is the only safe boundary for the next epoch. Records appended after
/// the lock is released belong to that next epoch rather than falling between
/// two independently captured checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessSnapshot {
    count: usize,
    end_checkpoint: WitnessCheckpoint,
}

impl WitnessSnapshot {
    /// Number of records copied into the caller's output slice.
    #[must_use]
    pub const fn count(self) -> usize {
        self.count
    }

    /// Atomic boundary at which the following epoch must begin.
    #[must_use]
    pub const fn end_checkpoint(self) -> WitnessCheckpoint {
        self.end_checkpoint
    }
}

impl WitnessCheckpoint {
    /// Reconstruct a checkpoint authenticated by durable receipt storage.
    ///
    /// This administrative recovery constructor must only receive coordinates
    /// verified against a signed receipt chain. Ordinary request data must not
    /// be promoted into a checkpoint through this API.
    #[must_use]
    pub const fn trusted_resume(next_sequence: u64, chain_hash: u64) -> Self {
        Self {
            next_sequence,
            chain_hash,
        }
    }

    /// Sequence number of the first record after this checkpoint.
    #[must_use]
    pub const fn next_sequence(self) -> u64 {
        self.next_sequence
    }

    /// Full internal chain hash immediately before the next record.
    #[must_use]
    pub const fn chain_hash(self) -> u64 {
        self.chain_hash
    }
}

/// Why a checkpoint-relative snapshot could not be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSinceError {
    /// The checkpoint refers to a sequence later than the current log head.
    FutureCheckpoint,
    /// At least one requested record has already been overwritten by the ring.
    RecordsOverwritten,
    /// The caller's output slice cannot hold the complete epoch.
    OutputTooSmall {
        /// Number of records required to return the epoch atomically.
        required: usize,
    },
    /// A retained ring slot did not carry the expected sequence.
    SequenceMismatch,
}

impl core::fmt::Display for SnapshotSinceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FutureCheckpoint => f.write_str("witness checkpoint is ahead of the log"),
            Self::RecordsOverwritten => f.write_str("witness records were overwritten"),
            Self::OutputTooSmall { required } => {
                write!(f, "witness output needs {required} records")
            }
            Self::SequenceMismatch => f.write_str("witness ring sequence mismatch"),
        }
    }
}

impl<const N: usize> WitnessLog<N> {
    /// Compile-time assertion: N must be greater than zero.
    ///
    /// Using a const item inside the impl block causes a compilation
    /// error when `N == 0` because dividing by zero is a const-eval
    /// failure. This replaces the previous `assert!(N > 0)` runtime
    /// panic with a hard compile-time rejection.
    const ASSERT_N_NONZERO: () = assert!(N > 0, "witness log capacity must be > 0");

    /// Creates a new empty witness log.
    ///
    /// # Compile-time invariant
    ///
    /// `N` must be greater than zero. Attempting to instantiate
    /// `WitnessLog<0>` is a compile-time error.
    #[must_use]
    pub fn new() -> Self {
        // Reference the const to ensure the compile-time check fires.
        let () = Self::ASSERT_N_NONZERO;
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
    ///
    /// # Hash truncation
    ///
    /// The internal chain hash is a full 64-bit FNV-1a value, but the
    /// `WitnessRecord` fields `prev_hash` and `record_hash` are 32-bit
    /// (constrained by the 64-byte record layout, ADR-134). We use
    /// XOR-folding (`high32 ^ low32`) rather than simple `as u32`
    /// truncation to preserve entropy from both halves of the hash.
    ///
    /// **Future migration note:** When SHA-256 is adopted (TEE ADR),
    /// the record format should be revised to use 64-bit (or wider)
    /// hash fields, which will require a witness format version bump.
    pub fn append(&self, mut record: WitnessRecord) -> u64 {
        let mut inner = self.inner.lock();
        let seq = inner.sequence;
        let prev_hash = inner.chain_hash;

        record.sequence = seq;
        record.prev_hash = fold_u64_to_u32(prev_hash);

        let chain = compute_chain_hash(prev_hash, seq);
        record.record_hash = fold_u64_to_u32(chain);

        let pos = inner.write_pos;
        inner.records[pos] = record;
        inner.write_pos = (pos + 1) % N;
        inner.chain_hash = chain;
        inner.sequence = seq.wrapping_add(1);
        inner.total_emitted += 1;

        seq
    }

    /// Appends a pre-built witness record with signing (ADR-142 Phase 4).
    ///
    /// Like [`append`], but after filling `sequence`, `prev_hash`, and
    /// `record_hash`, signs the fully-populated record using the provided
    /// [`WitnessSigner`] and stores the signature in the `aux` field.
    ///
    /// This ensures the signature covers all fields including chain-hash
    /// metadata, unlike signing before append.
    pub fn signed_append<S: crate::signer::WitnessSigner>(
        &self,
        mut record: WitnessRecord,
        signer: &S,
    ) -> u64 {
        let mut inner = self.inner.lock();
        let seq = inner.sequence;
        let prev_hash = inner.chain_hash;

        record.sequence = seq;
        record.prev_hash = fold_u64_to_u32(prev_hash);

        let chain = compute_chain_hash(prev_hash, seq);
        record.record_hash = fold_u64_to_u32(chain);

        // Sign the fully-populated record (all chain-hash fields set).
        record.aux = signer.sign(&record);

        let pos = inner.write_pos;
        inner.records[pos] = record;
        inner.write_pos = (pos + 1) % N;
        inner.chain_hash = chain;
        inner.sequence = seq.wrapping_add(1);
        inner.total_emitted += 1;

        seq
    }

    /// Returns the total number of records ever emitted.
    pub fn total_emitted(&self) -> u64 {
        self.inner.lock().total_emitted
    }

    /// Capture the current sequence and full chain hash under one lock.
    #[must_use]
    pub fn checkpoint(&self) -> WitnessCheckpoint {
        let inner = self.inner.lock();
        WitnessCheckpoint {
            next_sequence: inner.sequence,
            chain_hash: inner.chain_hash,
        }
    }

    /// Copy every record emitted after `checkpoint` in sequence order.
    ///
    /// This operation is all or nothing. It refuses partial output and refuses
    /// epochs whose earliest records have wrapped out of the ring, because
    /// either condition would make a cryptographic epoch receipt incomplete.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotSinceError::FutureCheckpoint`] for an impossible
    /// boundary, [`SnapshotSinceError::RecordsOverwritten`] after ring wrap,
    /// [`SnapshotSinceError::OutputTooSmall`] when `out` is undersized, or
    /// [`SnapshotSinceError::SequenceMismatch`] if retained state is corrupt.
    pub fn snapshot_since(
        &self,
        checkpoint: WitnessCheckpoint,
        out: &mut [WitnessRecord],
    ) -> Result<WitnessSnapshot, SnapshotSinceError> {
        let inner = self.inner.lock();
        if checkpoint.next_sequence > inner.sequence {
            return Err(SnapshotSinceError::FutureCheckpoint);
        }

        let capacity = u64::try_from(N).map_err(|_| SnapshotSinceError::RecordsOverwritten)?;
        let retained_start = inner.sequence.saturating_sub(capacity);
        if checkpoint.next_sequence < retained_start {
            return Err(SnapshotSinceError::RecordsOverwritten);
        }

        let required_u64 = inner.sequence - checkpoint.next_sequence;
        let required =
            usize::try_from(required_u64).map_err(|_| SnapshotSinceError::RecordsOverwritten)?;
        if out.len() < required {
            return Err(SnapshotSinceError::OutputTooSmall { required });
        }

        for (offset, slot) in out.iter_mut().enumerate().take(required) {
            let offset =
                u64::try_from(offset).map_err(|_| SnapshotSinceError::RecordsOverwritten)?;
            let sequence = checkpoint
                .next_sequence
                .checked_add(offset)
                .ok_or(SnapshotSinceError::SequenceMismatch)?;
            let ring_index = usize::try_from(sequence % capacity)
                .map_err(|_| SnapshotSinceError::SequenceMismatch)?;
            let record = inner.records[ring_index];
            if record.sequence != sequence {
                return Err(SnapshotSinceError::SequenceMismatch);
            }
            *slot = record;
        }
        Ok(WitnessSnapshot {
            count: required,
            end_checkpoint: WitnessCheckpoint {
                next_sequence: inner.sequence,
                chain_hash: inner.chain_hash,
            },
        })
    }

    /// Returns the number of records currently in the buffer.
    #[allow(clippy::cast_possible_truncation)]
    pub fn len(&self) -> usize {
        let total = self.inner.lock().total_emitted;
        // Safe: if total < N then total fits in usize since N is usize.
        if total >= N as u64 {
            N
        } else {
            total as usize
        }
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

    // -- signed_append tests (ADR-142 Phase 4) -----------------------------

    #[test]
    fn test_signed_append_sets_aux() {
        use crate::signer::default_signer;

        let log = WitnessLog::<16>::new();
        let signer = default_signer();

        let record = make_record(ActionKind::PartitionCreate, 1, 100, 1000);
        let seq = log.signed_append(record, &signer);
        assert_eq!(seq, 0);

        let stored = log.get(0).unwrap();
        // The aux field should be non-zero (signed).
        assert_ne!(stored.aux, [0u8; 8]);
    }

    #[test]
    fn test_signed_append_signature_verifiable() {
        use crate::signer::{default_signer, WitnessSigner};

        let log = WitnessLog::<16>::new();
        let signer = default_signer();

        let record = make_record(ActionKind::CapabilityGrant, 2, 200, 2000);
        log.signed_append(record, &signer);

        let stored = log.get(0).unwrap();
        // The stored record's signature should verify.
        assert!(signer.verify(&stored));
    }

    #[test]
    fn test_signed_append_chain_hashes_included() {
        use crate::signer::{default_signer, WitnessSigner};

        let log = WitnessLog::<16>::new();
        let signer = default_signer();

        // Append two signed records.
        log.signed_append(
            make_record(ActionKind::PartitionCreate, 1, 10, 100),
            &signer,
        );
        log.signed_append(
            make_record(ActionKind::CapabilityGrant, 1, 20, 200),
            &signer,
        );

        let r0 = log.get(0).unwrap();
        let r1 = log.get(1).unwrap();

        // Chain hashes should be set.
        assert_ne!(r1.prev_hash, 0);
        // Both records should verify.
        assert!(signer.verify(&r0));
        assert!(signer.verify(&r1));
    }

    #[test]
    fn test_signed_append_tampered_record_fails_verify() {
        use crate::signer::{default_signer, WitnessSigner};

        let log = WitnessLog::<16>::new();
        let signer = default_signer();

        log.signed_append(
            make_record(ActionKind::PartitionCreate, 1, 100, 1000),
            &signer,
        );

        let mut stored = log.get(0).unwrap();
        // Tamper with the record.
        stored.actor_partition_id = 999;
        // Verify should fail.
        assert!(!signer.verify(&stored));
    }

    #[test]
    fn checkpoint_snapshot_is_contiguous_and_complete() {
        let log = WitnessLog::<8>::new();
        log.append(make_record(ActionKind::ContextRead, 1, 1, 1));
        let checkpoint = log.checkpoint();
        log.append(make_record(ActionKind::ContextResolve, 1, 2, 2));
        log.append(make_record(ActionKind::ContextRead, 1, 3, 3));

        let mut out = [WitnessRecord::zeroed(); 4];
        let snapshot = log.snapshot_since(checkpoint, &mut out).unwrap();
        assert_eq!(snapshot.count(), 2);
        assert_eq!(snapshot.end_checkpoint(), log.checkpoint());
        assert_eq!(out[0].sequence, checkpoint.next_sequence());
        assert_eq!(out[1].sequence, checkpoint.next_sequence() + 1);
    }

    #[test]
    fn checkpoint_snapshot_refuses_partial_output() {
        let log = WitnessLog::<8>::new();
        let checkpoint = log.checkpoint();
        log.append(make_record(ActionKind::ContextRead, 1, 1, 1));
        log.append(make_record(ActionKind::ContextRead, 1, 2, 2));

        let mut out = [WitnessRecord::zeroed(); 1];
        assert_eq!(
            log.snapshot_since(checkpoint, &mut out),
            Err(SnapshotSinceError::OutputTooSmall { required: 2 })
        );
    }

    #[test]
    fn checkpoint_snapshot_detects_ring_wrap() {
        let log = WitnessLog::<2>::new();
        let checkpoint = log.checkpoint();
        for target in 0..3 {
            log.append(make_record(ActionKind::ContextRead, 1, target, target));
        }
        let mut out = [WitnessRecord::zeroed(); 3];
        assert_eq!(
            log.snapshot_since(checkpoint, &mut out),
            Err(SnapshotSinceError::RecordsOverwritten)
        );
    }
}
