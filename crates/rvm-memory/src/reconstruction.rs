//! Dormant state reconstruction pipeline (ADR-136).
//!
//! Dormant memory is not stored as raw bytes. Instead, it is stored as a
//! checkpoint snapshot plus a sequence of witness-recorded deltas. To restore
//! a dormant region to the warm tier, the reconstruction pipeline:
//!
//! 1. Loads the checkpoint (compressed with LZ4).
//! 2. Applies the witness delta log in sequence order.
//! 3. Validates the final state hash against the expected value.
//!
//! ## Compression
//!
//! The pipeline uses a simple byte-level compression stub. In production,
//! this would be backed by `lz4_flex` or a hardware compression engine.
//! The stub is sufficient for correctness testing.
//!
//! ## No-std Compatibility
//!
//! All operations work on caller-provided fixed-size buffers. No heap
//! allocation occurs.

use rvm_types::{OwnedRegionId, RvmError, RvmResult};

/// A checkpoint identifier (references a stored compressed snapshot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointId(u64);

impl CheckpointId {
    /// Create a new checkpoint identifier.
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

/// A single delta entry from the witness log.
///
/// Represents a write operation that occurred between the checkpoint
/// and the current state. Applied in sequence order during reconstruction.
#[derive(Debug, Clone, Copy)]
pub struct WitnessDelta {
    /// Sequence number in the witness log.
    pub sequence: u64,
    /// Offset within the region (in bytes) where the write occurred.
    pub offset: u32,
    /// Length of the data written (in bytes).
    pub length: u16,
    /// FNV-1a hash of the written data for integrity verification.
    pub data_hash: u64,
}

/// A compressed checkpoint snapshot.
///
/// Contains the compressed region contents at a known-good state,
/// plus metadata for verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedCheckpoint {
    /// Checkpoint identifier.
    pub id: CheckpointId,
    /// Region this checkpoint belongs to.
    pub region_id: OwnedRegionId,
    /// Witness sequence number at checkpoint creation time.
    pub witness_sequence: u64,
    /// FNV-1a hash of the uncompressed data.
    pub uncompressed_hash: u64,
    /// Size of the uncompressed data in bytes.
    pub uncompressed_size: u32,
    /// Size of the compressed data in bytes.
    pub compressed_size: u32,
}

/// Result of a reconstruction operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconstructionResult {
    /// The region that was reconstructed.
    pub region_id: OwnedRegionId,
    /// Number of bytes in the reconstructed state.
    pub size_bytes: u32,
    /// Number of deltas applied.
    pub deltas_applied: u32,
    /// Hash of the final reconstructed state.
    pub final_hash: u64,
}

/// The reconstruction pipeline.
///
/// Orchestrates checkpoint decompression and delta application to
/// reconstruct dormant memory regions.
///
/// `MAX_DELTAS` is the maximum number of witness deltas that can be
/// buffered during a single reconstruction operation.
pub struct ReconstructionPipeline<const MAX_DELTAS: usize> {
    /// Pending deltas to apply during reconstruction.
    deltas: [Option<WitnessDelta>; MAX_DELTAS],
    /// Number of deltas currently buffered.
    delta_count: usize,
}

impl<const MAX_DELTAS: usize> Default for ReconstructionPipeline<MAX_DELTAS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_DELTAS: usize> ReconstructionPipeline<MAX_DELTAS> {
    /// Sentinel value for empty delta slots.
    const EMPTY_DELTA: Option<WitnessDelta> = None;

    /// Create a new reconstruction pipeline.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deltas: [Self::EMPTY_DELTA; MAX_DELTAS],
            delta_count: 0,
        }
    }

    /// Return the number of buffered deltas.
    #[must_use]
    pub const fn delta_count(&self) -> usize {
        self.delta_count
    }

    /// Clear all buffered deltas.
    pub fn clear(&mut self) {
        for slot in &mut self.deltas {
            *slot = None;
        }
        self.delta_count = 0;
    }

    /// Add a witness delta to the reconstruction buffer.
    ///
    /// Deltas must be added in sequence order.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::ResourceLimitExceeded`] if the buffer is full.
    /// Returns [`RvmError::WitnessChainBroken`] if the delta is out of sequence.
    pub fn add_delta(&mut self, delta: WitnessDelta) -> RvmResult<()> {
        if self.delta_count >= MAX_DELTAS {
            return Err(RvmError::ResourceLimitExceeded);
        }

        // Verify sequence ordering.
        if self.delta_count > 0 {
            if let Some(last) = &self.deltas[self.delta_count - 1] {
                if delta.sequence <= last.sequence {
                    return Err(RvmError::WitnessChainBroken);
                }
            }
        }

        self.deltas[self.delta_count] = Some(delta);
        self.delta_count += 1;
        Ok(())
    }

    /// Reconstruct a dormant region from a checkpoint and the buffered deltas.
    ///
    /// # Parameters
    ///
    /// - `checkpoint`: Metadata about the compressed checkpoint.
    /// - `compressed_data`: The compressed checkpoint bytes.
    /// - `output`: Buffer to write the reconstructed region into. Must be
    ///   at least `checkpoint.uncompressed_size` bytes.
    /// - `delta_data_fn`: A function that, given a `WitnessDelta`, returns
    ///   a slice of the delta's data bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::CheckpointCorrupted`] if decompression fails, the
    /// hash does not match, or a delta is out of bounds.
    /// Returns [`RvmError::ResourceLimitExceeded`] if buffers are too small.
    /// Returns [`RvmError::WitnessVerificationFailed`] if a delta's data hash
    /// does not match.
    pub fn reconstruct<F>(
        &self,
        checkpoint: &CompressedCheckpoint,
        compressed_data: &[u8],
        output: &mut [u8],
        delta_data_fn: F,
    ) -> RvmResult<ReconstructionResult>
    where
        F: Fn(&WitnessDelta) -> &[u8],
    {
        let uncompressed_size = checkpoint.uncompressed_size as usize;

        // Validate buffer sizes.
        if compressed_data.len() < checkpoint.compressed_size as usize {
            return Err(RvmError::CheckpointCorrupted);
        }
        if output.len() < uncompressed_size {
            return Err(RvmError::ResourceLimitExceeded);
        }

        // Step 1: Decompress the checkpoint into the output buffer.
        let decompressed_size = decompress(
            &compressed_data[..checkpoint.compressed_size as usize],
            &mut output[..uncompressed_size],
        )?;

        if decompressed_size != uncompressed_size {
            return Err(RvmError::CheckpointCorrupted);
        }

        // Step 2: Verify the checkpoint hash.
        let hash = fnv1a_hash(&output[..uncompressed_size]);
        if hash != checkpoint.uncompressed_hash {
            return Err(RvmError::CheckpointCorrupted);
        }

        // Step 3: Apply deltas in sequence order.
        let mut deltas_applied = 0u32;
        for i in 0..self.delta_count {
            if let Some(delta) = &self.deltas[i] {
                let data = delta_data_fn(delta);

                // Validate delta bounds.
                let end = delta.offset as usize + delta.length as usize;
                if end > uncompressed_size {
                    return Err(RvmError::CheckpointCorrupted);
                }
                if data.len() < delta.length as usize {
                    return Err(RvmError::CheckpointCorrupted);
                }

                // Verify delta data integrity.
                let data_hash = fnv1a_hash(&data[..delta.length as usize]);
                if data_hash != delta.data_hash {
                    return Err(RvmError::WitnessVerificationFailed);
                }

                // Apply the delta.
                let offset = delta.offset as usize;
                let length = delta.length as usize;
                output[offset..offset + length].copy_from_slice(&data[..length]);
                deltas_applied += 1;
            }
        }

        // Compute final hash.
        let final_hash = fnv1a_hash(&output[..uncompressed_size]);

        #[allow(clippy::cast_possible_truncation)]
        Ok(ReconstructionResult {
            region_id: checkpoint.region_id,
            size_bytes: uncompressed_size as u32,
            deltas_applied,
            final_hash,
        })
    }
}

/// Create a compressed checkpoint from raw region data.
///
/// # Parameters
///
/// - `region_id`: The region being checkpointed.
/// - `checkpoint_id`: Unique ID for this checkpoint.
/// - `witness_sequence`: Current witness sequence number.
/// - `data`: The uncompressed region contents.
/// - `compressed_out`: Buffer to write compressed data into.
///
/// # Returns
///
/// A tuple of (`CompressedCheckpoint`, compressed byte count).
///
/// # Errors
///
/// Returns [`RvmError::ResourceLimitExceeded`] if the data is empty or
/// the output buffer is too small.
pub fn create_checkpoint(
    region_id: OwnedRegionId,
    checkpoint_id: CheckpointId,
    witness_sequence: u64,
    data: &[u8],
    compressed_out: &mut [u8],
) -> RvmResult<(CompressedCheckpoint, usize)> {
    if data.is_empty() {
        return Err(RvmError::ResourceLimitExceeded);
    }

    let uncompressed_hash = fnv1a_hash(data);
    let compressed_size = compress(data, compressed_out)?;

    #[allow(clippy::cast_possible_truncation)]
    let checkpoint = CompressedCheckpoint {
        id: checkpoint_id,
        region_id,
        witness_sequence,
        uncompressed_hash,
        uncompressed_size: data.len() as u32,
        compressed_size: compressed_size as u32,
    };

    Ok((checkpoint, compressed_size))
}

// --- LZ4-style RLE Compression ---
//
// A simplified LZ4-inspired compressor for dormant tier data.
// Uses run-length encoding for zero runs and literal copy for non-zero
// segments. This provides meaningful compression for memory snapshots
// (which tend to be zero-heavy) without requiring the full lz4_flex
// dependency.
//
// Format:
//   [4-byte uncompressed length (LE)]
//   Sequence of blocks:
//     Tag byte:
//       0x00 = Zero run:  next 2 bytes (LE u16) = run length
//       0x01 = Literal:   next 2 bytes (LE u16) = literal length, then N literal bytes
//
// This is a v1 compressor suitable for correctness; a future version
// may use full LZ4 frame format with match copying.

/// Tag byte for a zero-run block.
const TAG_ZERO_RUN: u8 = 0x00;
/// Tag byte for a literal block.
const TAG_LITERAL: u8 = 0x01;

/// Compress `input` into `output` using simplified RLE compression.
///
/// Returns the number of bytes written to `output`.
fn compress(input: &[u8], output: &mut [u8]) -> RvmResult<usize> {
    // Minimum output: 4-byte header. Even empty-ish data needs the header.
    if output.len() < 4 {
        return Err(RvmError::ResourceLimitExceeded);
    }

    // Write uncompressed length header.
    #[allow(clippy::cast_possible_truncation)]
    let len_bytes = (input.len() as u32).to_le_bytes();
    output[0..4].copy_from_slice(&len_bytes);

    let mut out_pos = 4;
    let mut in_pos = 0;

    while in_pos < input.len() {
        if input[in_pos] == 0 {
            // Count consecutive zeros.
            let run_start = in_pos;
            while in_pos < input.len() && input[in_pos] == 0 && (in_pos - run_start) < 0xFFFF {
                in_pos += 1;
            }
            let run_len = in_pos - run_start;

            // Write zero-run block: tag + u16 length.
            if out_pos + 3 > output.len() {
                return Err(RvmError::ResourceLimitExceeded);
            }
            output[out_pos] = TAG_ZERO_RUN;
            #[allow(clippy::cast_possible_truncation)]
            let rl = (run_len as u16).to_le_bytes();
            output[out_pos + 1] = rl[0];
            output[out_pos + 2] = rl[1];
            out_pos += 3;
        } else {
            // Collect non-zero literal bytes.
            let lit_start = in_pos;
            while in_pos < input.len() && input[in_pos] != 0 && (in_pos - lit_start) < 0xFFFF {
                in_pos += 1;
            }
            let lit_len = in_pos - lit_start;

            // Write literal block: tag + u16 length + data.
            if out_pos + 3 + lit_len > output.len() {
                return Err(RvmError::ResourceLimitExceeded);
            }
            output[out_pos] = TAG_LITERAL;
            #[allow(clippy::cast_possible_truncation)]
            let ll = (lit_len as u16).to_le_bytes();
            output[out_pos + 1] = ll[0];
            output[out_pos + 2] = ll[1];
            output[out_pos + 3..out_pos + 3 + lit_len]
                .copy_from_slice(&input[lit_start..lit_start + lit_len]);
            out_pos += 3 + lit_len;
        }
    }

    Ok(out_pos)
}

/// Decompress `input` into `output`. Returns the number of bytes written.
fn decompress(input: &[u8], output: &mut [u8]) -> RvmResult<usize> {
    if input.len() < 4 {
        return Err(RvmError::CheckpointCorrupted);
    }

    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&input[0..4]);
    let uncompressed_len = u32::from_le_bytes(len_bytes) as usize;

    if output.len() < uncompressed_len {
        return Err(RvmError::ResourceLimitExceeded);
    }

    let mut in_pos = 4;
    let mut out_pos = 0;

    while in_pos < input.len() && out_pos < uncompressed_len {
        if in_pos + 3 > input.len() {
            return Err(RvmError::CheckpointCorrupted);
        }
        let tag = input[in_pos];
        let block_len =
            u16::from_le_bytes([input[in_pos + 1], input[in_pos + 2]]) as usize;
        in_pos += 3;

        match tag {
            TAG_ZERO_RUN => {
                if out_pos + block_len > uncompressed_len {
                    return Err(RvmError::CheckpointCorrupted);
                }
                for b in &mut output[out_pos..out_pos + block_len] {
                    *b = 0;
                }
                out_pos += block_len;
            }
            TAG_LITERAL => {
                if in_pos + block_len > input.len() {
                    return Err(RvmError::CheckpointCorrupted);
                }
                if out_pos + block_len > uncompressed_len {
                    return Err(RvmError::CheckpointCorrupted);
                }
                output[out_pos..out_pos + block_len]
                    .copy_from_slice(&input[in_pos..in_pos + block_len]);
                in_pos += block_len;
                out_pos += block_len;
            }
            _ => {
                return Err(RvmError::CheckpointCorrupted);
            }
        }
    }

    if out_pos != uncompressed_len {
        return Err(RvmError::CheckpointCorrupted);
    }

    Ok(uncompressed_len)
}

/// FNV-1a 64-bit hash (same algorithm as `rvm-types`).
fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(id: u64) -> OwnedRegionId {
        OwnedRegionId::new(id)
    }

    #[test]
    fn compress_decompress_round_trip() {
        let data = b"Hello, dormant memory reconstruction!";
        let mut compressed = [0u8; 256];
        let compressed_len = compress(data, &mut compressed).unwrap();
        // RLE format: 4-byte header + literal block(3 + data.len()).
        // All non-zero ASCII text → one literal block.
        assert_eq!(compressed_len, data.len() + 4 + 3);

        let mut decompressed = [0u8; 256];
        let decompressed_len =
            decompress(&compressed[..compressed_len], &mut decompressed).unwrap();
        assert_eq!(decompressed_len, data.len());
        assert_eq!(&decompressed[..decompressed_len], data.as_slice());
    }

    #[test]
    fn compress_empty_output_fails() {
        let data = b"data";
        let mut out = [0u8; 2];
        assert_eq!(
            compress(data, &mut out),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn decompress_truncated_fails() {
        let input = [0u8; 2]; // Too short for header.
        let mut out = [0u8; 256];
        assert_eq!(
            decompress(&input, &mut out),
            Err(RvmError::CheckpointCorrupted)
        );
    }

    #[test]
    fn fnv1a_hash_deterministic() {
        let data = b"test data";
        let h1 = fnv1a_hash(data);
        let h2 = fnv1a_hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a_hash_different_data() {
        let h1 = fnv1a_hash(b"alpha");
        let h2 = fnv1a_hash(b"beta");
        assert_ne!(h1, h2);
    }

    #[test]
    fn checkpoint_creation() {
        let data = b"region state snapshot";
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(100), 42, data, &mut compressed)
                .unwrap();

        assert_eq!(ckpt.id, CheckpointId::new(100));
        assert_eq!(ckpt.region_id, rid(1));
        assert_eq!(ckpt.witness_sequence, 42);
        assert_eq!(ckpt.uncompressed_size, data.len() as u32);
        assert_eq!(ckpt.compressed_size, csize as u32);
        assert_eq!(ckpt.uncompressed_hash, fnv1a_hash(data));
    }

    #[test]
    fn checkpoint_empty_data_fails() {
        let mut compressed = [0u8; 256];
        assert!(matches!(
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &[], &mut compressed),
            Err(RvmError::ResourceLimitExceeded)
        ));
    }

    #[test]
    fn pipeline_no_deltas() {
        let pipeline = ReconstructionPipeline::<16>::new();

        let data = b"original state";
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, data, &mut compressed)
                .unwrap();

        let mut output = [0u8; 256];
        let result = pipeline
            .reconstruct(&ckpt, &compressed[..csize], &mut output, |_| &[])
            .unwrap();

        assert_eq!(result.region_id, rid(1));
        assert_eq!(result.size_bytes, data.len() as u32);
        assert_eq!(result.deltas_applied, 0);
        assert_eq!(&output[..data.len()], data.as_slice());
    }

    #[test]
    fn pipeline_with_deltas() {
        let mut pipeline = ReconstructionPipeline::<16>::new();

        let data = b"Hello, World!!!"; // 15 bytes
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, data, &mut compressed)
                .unwrap();

        // Create a delta that overwrites "World" with "Rust!"
        let patch = b"Rust!";
        let delta = WitnessDelta {
            sequence: 1,
            offset: 7,
            length: 5,
            data_hash: fnv1a_hash(patch),
        };
        pipeline.add_delta(delta).unwrap();

        let mut output = [0u8; 256];
        let result = pipeline
            .reconstruct(&ckpt, &compressed[..csize], &mut output, |_d| {
                patch.as_slice()
            })
            .unwrap();

        assert_eq!(result.deltas_applied, 1);
        assert_eq!(&output[..15], b"Hello, Rust!!!!");
    }

    #[test]
    fn pipeline_multiple_deltas() {
        static PATCH1: [u8; 4] = [0xAA, 0xAA, 0xAA, 0xAA];
        static PATCH2: [u8; 4] = [0xBB, 0xBB, 0xBB, 0xBB];

        let mut pipeline = ReconstructionPipeline::<16>::new();

        let data = [0u8; 16];
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &data, &mut compressed)
                .unwrap();

        // Delta 1: write 0xAA at offset 0, length 4.
        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 4,
                data_hash: fnv1a_hash(&PATCH1),
            })
            .unwrap();

        // Delta 2: write 0xBB at offset 8, length 4.
        pipeline
            .add_delta(WitnessDelta {
                sequence: 2,
                offset: 8,
                length: 4,
                data_hash: fnv1a_hash(&PATCH2),
            })
            .unwrap();

        let mut output = [0u8; 256];
        let result = pipeline
            .reconstruct(&ckpt, &compressed[..csize], &mut output, |d| {
                // Return data based on sequence number.
                if d.sequence == 1 {
                    &PATCH1
                } else {
                    &PATCH2
                }
            })
            .unwrap();

        assert_eq!(result.deltas_applied, 2);
        assert_eq!(&output[0..4], &[0xAA; 4]);
        assert_eq!(&output[4..8], &[0x00; 4]);
        assert_eq!(&output[8..12], &[0xBB; 4]);
        assert_eq!(&output[12..16], &[0x00; 4]);
    }

    #[test]
    fn pipeline_out_of_order_delta_fails() {
        let mut pipeline = ReconstructionPipeline::<16>::new();
        pipeline
            .add_delta(WitnessDelta {
                sequence: 5,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        // Adding a delta with sequence <= 5 should fail.
        assert_eq!(
            pipeline.add_delta(WitnessDelta {
                sequence: 3,
                offset: 0,
                length: 1,
                data_hash: 0,
            }),
            Err(RvmError::WitnessChainBroken)
        );
    }

    #[test]
    fn pipeline_overflow_fails() {
        let mut pipeline = ReconstructionPipeline::<2>::new();
        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        pipeline
            .add_delta(WitnessDelta {
                sequence: 2,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        assert_eq!(
            pipeline.add_delta(WitnessDelta {
                sequence: 3,
                offset: 0,
                length: 1,
                data_hash: 0,
            }),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn pipeline_clear() {
        let mut pipeline = ReconstructionPipeline::<4>::new();
        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        assert_eq!(pipeline.delta_count(), 1);

        pipeline.clear();
        assert_eq!(pipeline.delta_count(), 0);
    }

    #[test]
    fn reconstruction_corrupted_checkpoint_hash() {
        let pipeline = ReconstructionPipeline::<16>::new();

        let data = b"valid data";
        let mut compressed = [0u8; 256];
        let (mut ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, data, &mut compressed)
                .unwrap();

        // Corrupt the expected hash.
        ckpt.uncompressed_hash = 0xDEAD_BEEF;

        let mut output = [0u8; 256];
        assert_eq!(
            pipeline.reconstruct(&ckpt, &compressed[..csize], &mut output, |_| &[]),
            Err(RvmError::CheckpointCorrupted)
        );
    }

    #[test]
    fn reconstruction_delta_hash_mismatch() {
        let mut pipeline = ReconstructionPipeline::<16>::new();

        let data = b"some state";
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, data, &mut compressed)
                .unwrap();

        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 4,
                data_hash: 0xBAD_0000, // Wrong hash.
            })
            .unwrap();

        let patch = b"good";
        let mut output = [0u8; 256];
        assert_eq!(
            pipeline.reconstruct(
                &ckpt,
                &compressed[..csize],
                &mut output,
                |_| patch.as_slice()
            ),
            Err(RvmError::WitnessVerificationFailed)
        );
    }

    #[test]
    fn reconstruction_delta_out_of_bounds() {
        let mut pipeline = ReconstructionPipeline::<16>::new();

        let data = b"short";
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, data, &mut compressed)
                .unwrap();

        let patch = b"overrun!";
        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 3,
                length: 8, // Would extend past end of 5-byte region.
                data_hash: fnv1a_hash(patch),
            })
            .unwrap();

        let mut output = [0u8; 256];
        assert_eq!(
            pipeline.reconstruct(
                &ckpt,
                &compressed[..csize],
                &mut output,
                |_| patch.as_slice()
            ),
            Err(RvmError::CheckpointCorrupted)
        );
    }

    #[test]
    fn checkpoint_id_accessors() {
        let id = CheckpointId::new(42);
        assert_eq!(id.as_u64(), 42);
    }

    // ---------------------------------------------------------------
    // Reconstruction with maximum delta count
    // ---------------------------------------------------------------

    #[test]
    fn reconstruction_at_max_delta_capacity() {
        // Pipeline with capacity 4, fill it to max.
        let mut pipeline = ReconstructionPipeline::<4>::new();

        let data = [0u8; 32];
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &data, &mut compressed)
                .unwrap();

        // Add exactly 4 deltas (each writes 1 byte at a different offset).
        static PATCHES: [[u8; 1]; 4] = [[0xAA], [0xBB], [0xCC], [0xDD]];
        for (i, patch) in PATCHES.iter().enumerate() {
            pipeline
                .add_delta(WitnessDelta {
                    sequence: (i + 1) as u64,
                    offset: (i * 4) as u32,
                    length: 1,
                    data_hash: fnv1a_hash(patch),
                })
                .unwrap();
        }
        assert_eq!(pipeline.delta_count(), 4);

        // Adding one more should fail.
        assert_eq!(
            pipeline.add_delta(WitnessDelta {
                sequence: 5,
                offset: 20,
                length: 1,
                data_hash: 0,
            }),
            Err(RvmError::ResourceLimitExceeded)
        );

        // Reconstruct with all 4 deltas.
        let mut output = [0u8; 256];
        let result = pipeline
            .reconstruct(&ckpt, &compressed[..csize], &mut output, |d| {
                &PATCHES[(d.sequence - 1) as usize]
            })
            .unwrap();

        assert_eq!(result.deltas_applied, 4);
        assert_eq!(output[0], 0xAA);
        assert_eq!(output[4], 0xBB);
        assert_eq!(output[8], 0xCC);
        assert_eq!(output[12], 0xDD);
    }

    #[test]
    fn reconstruction_single_delta_capacity() {
        let mut pipeline = ReconstructionPipeline::<1>::new();

        let data = [0xFF; 8];
        let mut compressed = [0u8; 64];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &data, &mut compressed)
                .unwrap();

        static PATCH_ZERO: [u8; 1] = [0x00];
        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 1,
                data_hash: fnv1a_hash(&PATCH_ZERO),
            })
            .unwrap();

        // Second delta overflows.
        assert_eq!(
            pipeline.add_delta(WitnessDelta {
                sequence: 2,
                offset: 1,
                length: 1,
                data_hash: 0,
            }),
            Err(RvmError::ResourceLimitExceeded)
        );

        let mut output = [0u8; 64];
        let result = pipeline
            .reconstruct(&ckpt, &compressed[..csize], &mut output, |_| &PATCH_ZERO)
            .unwrap();
        assert_eq!(result.deltas_applied, 1);
        assert_eq!(output[0], 0x00);
        assert_eq!(output[1], 0xFF); // Unchanged.
    }

    #[test]
    fn reconstruction_clear_allows_reuse() {
        let mut pipeline = ReconstructionPipeline::<2>::new();

        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        pipeline
            .add_delta(WitnessDelta {
                sequence: 2,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        assert_eq!(pipeline.delta_count(), 2);

        pipeline.clear();
        assert_eq!(pipeline.delta_count(), 0);

        // Should be able to add 2 more after clear.
        pipeline
            .add_delta(WitnessDelta {
                sequence: 10,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        pipeline
            .add_delta(WitnessDelta {
                sequence: 11,
                offset: 0,
                length: 1,
                data_hash: 0,
            })
            .unwrap();
        assert_eq!(pipeline.delta_count(), 2);
    }

    #[test]
    fn reconstruction_output_buffer_too_small() {
        let pipeline = ReconstructionPipeline::<4>::new();

        let data = [0u8; 32];
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &data, &mut compressed)
                .unwrap();

        // Output buffer smaller than uncompressed size.
        let mut small_output = [0u8; 16];
        assert_eq!(
            pipeline.reconstruct(&ckpt, &compressed[..csize], &mut small_output, |_| &[]),
            Err(RvmError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn reconstruction_compressed_data_truncated() {
        let pipeline = ReconstructionPipeline::<4>::new();

        let data = [0u8; 32];
        let mut compressed = [0u8; 256];
        let (ckpt, _csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &data, &mut compressed)
                .unwrap();

        // Pass truncated compressed data.
        let mut output = [0u8; 256];
        assert_eq!(
            pipeline.reconstruct(&ckpt, &compressed[..2], &mut output, |_| &[]),
            Err(RvmError::CheckpointCorrupted)
        );
    }

    #[test]
    fn reconstruction_delta_data_shorter_than_length() {
        let mut pipeline = ReconstructionPipeline::<4>::new();

        let data = [0u8; 16];
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &data, &mut compressed)
                .unwrap();

        // Delta says length=4 but we return only 2 bytes.
        static SHORT_PATCH: [u8; 2] = [0xAA, 0xBB];
        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 4,
                data_hash: fnv1a_hash(&SHORT_PATCH),
            })
            .unwrap();

        let mut output = [0u8; 256];
        assert_eq!(
            pipeline.reconstruct(&ckpt, &compressed[..csize], &mut output, |_| &SHORT_PATCH),
            Err(RvmError::CheckpointCorrupted)
        );
    }

    #[test]
    fn reconstruction_final_hash_changes_with_deltas() {
        let data = b"original data!!"; // 15 bytes
        let mut compressed = [0u8; 256];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, data, &mut compressed)
                .unwrap();

        // Reconstruct without deltas.
        let pipeline_no_deltas = ReconstructionPipeline::<4>::new();
        let mut out1 = [0u8; 256];
        let r1 = pipeline_no_deltas
            .reconstruct(&ckpt, &compressed[..csize], &mut out1, |_| &[])
            .unwrap();

        // Reconstruct with one delta.
        let mut pipeline_with_delta = ReconstructionPipeline::<4>::new();
        static XPATCH: [u8; 1] = [b'X'];
        pipeline_with_delta
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 1,
                data_hash: fnv1a_hash(&XPATCH),
            })
            .unwrap();
        let mut out2 = [0u8; 256];
        let r2 = pipeline_with_delta
            .reconstruct(&ckpt, &compressed[..csize], &mut out2, |_| &XPATCH)
            .unwrap();

        // The final hashes should differ.
        assert_ne!(r1.final_hash, r2.final_hash);
    }

    #[test]
    fn reconstruction_overlapping_deltas() {
        // Two deltas that write to the same offset -- second one wins.
        let mut pipeline = ReconstructionPipeline::<4>::new();

        let data = [0u8; 8];
        let mut compressed = [0u8; 64];
        let (ckpt, csize) =
            create_checkpoint(rid(1), CheckpointId::new(1), 0, &data, &mut compressed)
                .unwrap();

        static FIRST: [u8; 2] = [0xAA, 0xAA];
        static SECOND: [u8; 2] = [0xBB, 0xBB];

        pipeline
            .add_delta(WitnessDelta {
                sequence: 1,
                offset: 0,
                length: 2,
                data_hash: fnv1a_hash(&FIRST),
            })
            .unwrap();
        pipeline
            .add_delta(WitnessDelta {
                sequence: 2,
                offset: 0,
                length: 2,
                data_hash: fnv1a_hash(&SECOND),
            })
            .unwrap();

        let mut output = [0u8; 64];
        let result = pipeline
            .reconstruct(&ckpt, &compressed[..csize], &mut output, |d| {
                if d.sequence == 1 { &FIRST } else { &SECOND }
            })
            .unwrap();

        assert_eq!(result.deltas_applied, 2);
        // Second delta overwrites the first.
        assert_eq!(&output[0..2], &[0xBB, 0xBB]);
    }

    // ---------------------------------------------------------------
    // RLE compression tests
    // ---------------------------------------------------------------

    #[test]
    fn compress_decompress_rle_round_trip() {
        let data = b"Hello, dormant memory reconstruction!";
        let mut compressed = [0u8; 256];
        let compressed_len = compress(data, &mut compressed).unwrap();

        let mut decompressed = [0u8; 256];
        let decompressed_len =
            decompress(&compressed[..compressed_len], &mut decompressed).unwrap();
        assert_eq!(decompressed_len, data.len());
        assert_eq!(&decompressed[..decompressed_len], data.as_slice());
    }

    #[test]
    fn compress_zero_heavy_data_achieves_ratio() {
        // 1024 bytes of mostly zeros should compress significantly.
        let mut data = [0u8; 1024];
        // Sprinkle some non-zero bytes.
        data[0] = 0xAA;
        data[512] = 0xBB;
        data[1023] = 0xCC;

        let mut compressed = [0u8; 1024];
        let compressed_len = compress(&data, &mut compressed).unwrap();

        // Should be much smaller than 1024 bytes.
        // Header(4) + zero_run(3) for first run of 0s is negligible vs 1024 raw.
        assert!(
            compressed_len < data.len() / 2,
            "compressed {compressed_len} should be less than {}",
            data.len() / 2
        );

        // Round-trip verification.
        let mut decompressed = [0u8; 1024];
        let decompressed_len =
            decompress(&compressed[..compressed_len], &mut decompressed).unwrap();
        assert_eq!(decompressed_len, 1024);
        assert_eq!(&decompressed[..], &data[..]);
    }

    #[test]
    fn compress_all_zeros() {
        let data = [0u8; 512];
        let mut compressed = [0u8; 64];
        let compressed_len = compress(&data, &mut compressed).unwrap();

        // Should be very small: header(4) + one zero-run block(3) = 7 bytes.
        assert_eq!(compressed_len, 7);

        let mut decompressed = [0u8; 512];
        let decompressed_len =
            decompress(&compressed[..compressed_len], &mut decompressed).unwrap();
        assert_eq!(decompressed_len, 512);
        assert_eq!(&decompressed[..], &data[..]);
    }

    #[test]
    fn compress_all_nonzero() {
        // All non-zero data should still round-trip, just with no compression gain.
        let data = [0xFFu8; 64];
        let mut compressed = [0u8; 256];
        let compressed_len = compress(&data, &mut compressed).unwrap();

        // Header(4) + literal block(3 + 64) = 71 bytes.
        assert_eq!(compressed_len, 4 + 3 + 64);

        let mut decompressed = [0u8; 64];
        let decompressed_len =
            decompress(&compressed[..compressed_len], &mut decompressed).unwrap();
        assert_eq!(decompressed_len, 64);
        assert_eq!(&decompressed[..], &data[..]);
    }

    #[test]
    fn compress_alternating_zero_nonzero() {
        // Pattern: [0, 0xAA, 0, 0xBB, 0, 0xCC] -- alternating.
        let data = [0, 0xAA, 0, 0xBB, 0, 0xCC];
        let mut compressed = [0u8; 128];
        let compressed_len = compress(&data, &mut compressed).unwrap();

        let mut decompressed = [0u8; 128];
        let decompressed_len =
            decompress(&compressed[..compressed_len], &mut decompressed).unwrap();
        assert_eq!(decompressed_len, data.len());
        assert_eq!(&decompressed[..data.len()], &data[..]);
    }

    #[test]
    fn decompress_invalid_tag() {
        // Craft invalid compressed data with an unknown tag byte.
        let mut bad = [0u8; 16];
        // Header: uncompressed length = 4.
        bad[0..4].copy_from_slice(&4u32.to_le_bytes());
        bad[4] = 0xFF; // Invalid tag.
        bad[5] = 4;
        bad[6] = 0;

        let mut output = [0u8; 16];
        assert_eq!(
            decompress(&bad[..7], &mut output),
            Err(RvmError::CheckpointCorrupted)
        );
    }

    #[test]
    fn compress_empty_input_round_trip() {
        // Empty input should produce just the 4-byte header.
        let data: [u8; 0] = [];
        let mut compressed = [0u8; 16];
        let compressed_len = compress(&data, &mut compressed).unwrap();
        assert_eq!(compressed_len, 4);

        let mut decompressed = [0u8; 1];
        let decompressed_len =
            decompress(&compressed[..compressed_len], &mut decompressed).unwrap();
        assert_eq!(decompressed_len, 0);
    }
}
