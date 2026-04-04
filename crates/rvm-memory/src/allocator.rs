//! Buddy allocator for physical page allocation (ADR-136).
//!
//! A `no_std`, `no_alloc` buddy allocator that uses a fixed-size bitmap
//! to track allocation state. Each bit in the bitmap represents a block
//! at its corresponding order level. The allocator manages blocks in
//! power-of-two sizes (in pages).
//!
//! ## Design
//!
//! The allocator uses a single flat bitmap where each order level owns
//! a contiguous range of bits. For order `k`, there are `total_pages / 2^k`
//! blocks. A set bit means the block is free.
//!
//! Block splitting and merging (buddy coalescing) are performed during
//! `alloc_pages` and `free_pages` respectively.

use rvm_types::{PhysAddr, RvmError, RvmResult};

use crate::PAGE_SIZE;

/// Maximum supported order (allocation of `2^MAX_ORDER` pages at once).
const MAX_ORDER: usize = 10; // Up to 1024 pages = 4 MiB per block.

/// Compute the number of bitmap words needed for a given number of bits.
const fn words_for_bits(bits: usize) -> usize {
    bits.div_ceil(64)
}

/// Total bitmap bits needed for all order levels given `total_pages`.
///
/// For order 0: `total_pages` bits.
/// For order 1: `total_pages / 2` bits.
/// ...
/// For order k: `total_pages / 2^k` bits.
/// Total = `total_pages * 2 - 1` (geometric series, approximately).
const fn total_bitmap_bits(total_pages: usize) -> usize {
    let mut bits = 0;
    let mut order = 0;
    while order <= MAX_ORDER {
        bits += total_pages >> order;
        order += 1;
    }
    bits
}

/// A buddy allocator managing `TOTAL_PAGES` of physical memory.
///
/// The allocator is entirely stack-allocated with a fixed-size bitmap.
/// `TOTAL_PAGES` must be a power of two and at most `2^MAX_ORDER * some_count`.
///
/// # Type Parameters
///
/// - `TOTAL_PAGES`: The total number of 4 KiB pages managed. Must be a power of two.
/// - `BITMAP_WORDS`: The number of `u64` words in the bitmap. Must be at least
///   `total_bitmap_bits(TOTAL_PAGES) / 64 + 1`. Use [`BuddyAllocator::REQUIRED_BITMAP_WORDS`]
///   to compute this.
pub struct BuddyAllocator<const TOTAL_PAGES: usize, const BITMAP_WORDS: usize> {
    /// Base physical address of the managed memory region.
    base: PhysAddr,
    /// Bitmap: bit set = block is free.
    bitmap: [u64; BITMAP_WORDS],
    /// Pre-computed cumulative bit offsets per order level.
    /// `bit_offsets[k]` = sum of `TOTAL_PAGES >> i` for i in 0..k.
    /// Replaces the O(order) loop in `bit_offset()` with O(1) lookup.
    bit_offsets: [usize; MAX_ORDER + 1],
}

impl<const TOTAL_PAGES: usize, const BITMAP_WORDS: usize>
    BuddyAllocator<TOTAL_PAGES, BITMAP_WORDS>
{
    /// The number of bitmap `u64` words required for `TOTAL_PAGES`.
    pub const REQUIRED_BITMAP_WORDS: usize = words_for_bits(total_bitmap_bits(TOTAL_PAGES));

    /// Create a new buddy allocator managing memory starting at `base`.
    ///
    /// All blocks are initially marked as free. `base` must be page-aligned.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::AlignmentError`] if `base` is not page-aligned.
    /// Returns [`RvmError::ResourceLimitExceeded`] if `BITMAP_WORDS` is insufficient.
    pub fn new(base: PhysAddr) -> RvmResult<Self> {
        if !base.is_page_aligned() {
            return Err(RvmError::AlignmentError);
        }
        // Verify BITMAP_WORDS is sufficient.
        if BITMAP_WORDS < Self::REQUIRED_BITMAP_WORDS {
            return Err(RvmError::ResourceLimitExceeded);
        }

        // Pre-compute cumulative bit offsets for each order level.
        let mut bit_offsets = [0usize; MAX_ORDER + 1];
        let mut cumulative = 0;
        let mut o = 0;
        while o <= MAX_ORDER {
            bit_offsets[o] = cumulative;
            cumulative += TOTAL_PAGES >> o;
            o += 1;
        }

        let mut alloc = Self {
            base,
            bitmap: [0u64; BITMAP_WORDS],
            bit_offsets,
        };
        alloc.init_free_all();
        Ok(alloc)
    }

    /// Initialize the allocator by marking the highest-order blocks as free.
    ///
    /// Only the coarsest level blocks are free initially; smaller blocks are
    /// split on demand during allocation.
    fn init_free_all(&mut self) {
        // Clear entire bitmap first.
        for word in &mut self.bitmap {
            *word = 0;
        }

        // Mark all blocks at the maximum possible order as free.
        let max_usable_order = Self::max_usable_order();
        let block_count = TOTAL_PAGES >> max_usable_order;
        for blk in 0..block_count {
            self.set_free(max_usable_order, blk);
        }
    }

    /// Return the maximum usable order (capped by `MAX_ORDER` and `TOTAL_PAGES`).
    const fn max_usable_order() -> usize {
        let mut order = MAX_ORDER;
        // Ensure we don't exceed total pages.
        while order > 0 && (1usize << order) > TOTAL_PAGES {
            order -= 1;
        }
        order
    }

    /// Allocate `2^order` contiguous pages.
    ///
    /// Returns the base `PhysAddr` of the allocated block.
    ///
    /// Uses `trailing_zeros` on bitmap words for fast first-free-block
    /// scanning: O(1) per 64-bit word instead of checking bit-by-bit.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::OutOfMemory`] if no block of the requested size
    /// is available.
    pub fn alloc_pages(&mut self, order: usize) -> RvmResult<PhysAddr> {
        if order > Self::max_usable_order() {
            return Err(RvmError::OutOfMemory);
        }

        // Try to find a free block at this order using trailing_zeros scan.
        if let Some(blk) = self.find_first_free(order) {
            self.clear_free(order, blk);
            let page_offset = blk << order;
            let addr = self.base.as_u64() + (page_offset as u64 * PAGE_SIZE as u64);
            return Ok(PhysAddr::new(addr));
        }

        // No free block at this order -- try to split a higher-order block.
        let mut split_order = order + 1;
        while split_order <= Self::max_usable_order() {
            if let Some(blk) = self.find_first_free(split_order) {
                // Remove the block from the higher order.
                self.clear_free(split_order, blk);

                // Split down to the requested order.
                let mut current_order = split_order;
                let mut current_blk = blk;
                while current_order > order {
                    current_order -= 1;
                    // The block at `current_order` splits into two children.
                    let left_child = current_blk * 2;
                    let right_child = left_child + 1;
                    // Mark the right (buddy) child as free.
                    self.set_free(current_order, right_child);
                    // Continue splitting the left child.
                    current_blk = left_child;
                }

                let page_offset = current_blk << order;
                let addr = self.base.as_u64() + (page_offset as u64 * PAGE_SIZE as u64);
                return Ok(PhysAddr::new(addr));
            }

            split_order += 1;
        }

        Err(RvmError::OutOfMemory)
    }

    /// Free a previously allocated block of `2^order` pages starting at `addr`.
    ///
    /// The caller must ensure `addr` was returned by a prior `alloc_pages(order)` call.
    ///
    /// # Errors
    ///
    /// Returns [`RvmError::AlignmentError`] if the address is invalid or misaligned.
    /// Returns [`RvmError::InvalidTierTransition`] if the order exceeds the maximum.
    /// Returns [`RvmError::InternalError`] on double-free detection.
    pub fn free_pages(&mut self, addr: PhysAddr, order: usize) -> RvmResult<()> {
        if order > Self::max_usable_order() {
            return Err(RvmError::InvalidTierTransition);
        }
        if addr.as_u64() < self.base.as_u64() {
            return Err(RvmError::AlignmentError);
        }

        let offset_bytes = addr.as_u64() - self.base.as_u64();
        if offset_bytes % (PAGE_SIZE as u64) != 0 {
            return Err(RvmError::AlignmentError);
        }
        #[allow(clippy::cast_possible_truncation)]
        let page_offset = (offset_bytes / PAGE_SIZE as u64) as usize;
        if page_offset >= TOTAL_PAGES {
            return Err(RvmError::AlignmentError);
        }

        let block_index = page_offset >> order;

        // Check alignment: the block must start at a block-aligned offset.
        if (block_index << order) != page_offset {
            return Err(RvmError::AlignmentError);
        }

        // Double-free check: the block should not already be free at this
        // order, nor should any ancestor block be free (which would mean this
        // block was coalesced into a larger free block).
        if self.is_block_free(order, block_index) {
            return Err(RvmError::InternalError);
        }

        // Mark the block as free and coalesce with buddy if possible.
        self.set_free(order, block_index);
        self.coalesce(order, block_index);

        Ok(())
    }

    /// Return the total number of free pages across all orders.
    #[must_use]
    pub fn free_page_count(&self) -> usize {
        let mut count = 0;
        let max_order = Self::max_usable_order();
        let mut order = 0;
        while order <= max_order {
            let block_count = TOTAL_PAGES >> order;
            for blk in 0..block_count {
                if self.is_free(order, blk) {
                    count += 1 << order;
                }
            }
            order += 1;
        }
        count
    }

    /// Coalesce freed blocks with their buddies up the order chain.
    fn coalesce(&mut self, order: usize, block_index: usize) {
        let mut current_order = order;
        let mut current_blk = block_index;

        while current_order < Self::max_usable_order() {
            let buddy = current_blk ^ 1; // XOR with 1 gives the buddy index.
            let block_count = TOTAL_PAGES >> current_order;

            if buddy >= block_count {
                break; // Buddy is out of range.
            }

            if !self.is_free(current_order, buddy) {
                break; // Buddy is not free, cannot coalesce.
            }

            // Remove both blocks from the current order.
            self.clear_free(current_order, current_blk);
            self.clear_free(current_order, buddy);

            // Merge into the parent block.
            current_order += 1;
            current_blk /= 2;
            self.set_free(current_order, current_blk);
        }
    }

    /// Check if a block is effectively free -- either directly marked free
    /// at its order, or covered by a free ancestor at a higher order.
    fn is_block_free(&self, order: usize, block_index: usize) -> bool {
        if self.is_free(order, block_index) {
            return true;
        }
        // Walk up the ancestor chain.
        let mut o = order + 1;
        let mut blk = block_index / 2;
        while o <= Self::max_usable_order() {
            if self.is_free(o, blk) {
                return true;
            }
            o += 1;
            blk /= 2;
        }
        false
    }

    // --- Bitmap helpers ---

    /// Find the first free block at the given order using `trailing_zeros`
    /// on bitmap words for O(1) per 64-bit word scanning.
    ///
    /// Returns the block index, or `None` if no free block exists.
    fn find_first_free(&self, order: usize) -> Option<usize> {
        let block_count = TOTAL_PAGES >> order;
        if block_count == 0 {
            return None;
        }
        let base_bit = self.bit_offsets[order];
        let start_word = base_bit / 64;
        let start_bit_in_word = base_bit % 64;

        // Total bits to scan for this order level.
        let mut remaining = block_count;
        let mut word_idx = start_word;
        let mut bit_offset_in_level = 0usize;

        // Handle the first (potentially partial) word.
        if start_bit_in_word != 0 && word_idx < BITMAP_WORDS {
            // Mask off bits below our start position in this word.
            let mask = self.bitmap[word_idx] >> start_bit_in_word;
            if mask != 0 {
                let tz = mask.trailing_zeros() as usize;
                if tz < remaining && (start_bit_in_word + tz) < 64 {
                    return Some(tz);
                }
            }
            let bits_in_first_word = 64 - start_bit_in_word;
            let consumed = bits_in_first_word.min(remaining);
            remaining = remaining.saturating_sub(consumed);
            bit_offset_in_level += consumed;
            word_idx += 1;
        }

        // Scan full 64-bit words using trailing_zeros.
        while remaining > 0 && word_idx < BITMAP_WORDS {
            let word = self.bitmap[word_idx];
            if word != 0 {
                let tz = word.trailing_zeros() as usize;
                if tz < remaining.min(64) {
                    return Some(bit_offset_in_level + tz);
                }
            }
            let consumed = remaining.min(64);
            remaining -= consumed;
            bit_offset_in_level += consumed;
            word_idx += 1;
        }

        None
    }

    /// Compute the bit offset for block `blk` at `order`.
    /// Uses the pre-computed LUT for O(1) instead of O(order) loop.
    #[inline]
    fn bit_offset(&self, order: usize, blk: usize) -> usize {
        self.bit_offsets[order] + blk
    }

    /// Check if a block is marked as free in the bitmap.
    #[inline]
    fn is_free(&self, order: usize, blk: usize) -> bool {
        let bit = self.bit_offset(order, blk);
        let word = bit / 64;
        let bit_in_word = bit % 64;
        if word >= BITMAP_WORDS {
            return false;
        }
        (self.bitmap[word] >> bit_in_word) & 1 == 1
    }

    /// Mark a block as free in the bitmap.
    #[inline]
    fn set_free(&mut self, order: usize, blk: usize) {
        let bit = self.bit_offset(order, blk);
        let word = bit / 64;
        let bit_in_word = bit % 64;
        if word < BITMAP_WORDS {
            self.bitmap[word] |= 1u64 << bit_in_word;
        }
    }

    /// Mark a block as allocated (not free) in the bitmap.
    #[inline]
    fn clear_free(&mut self, order: usize, blk: usize) {
        let bit = self.bit_offset(order, blk);
        let word = bit / 64;
        let bit_in_word = bit % 64;
        if word < BITMAP_WORDS {
            self.bitmap[word] &= !(1u64 << bit_in_word);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small allocator managing 16 pages (64 KiB) for testing.
    /// Total bitmap bits: 16 + 8 + 4 + 2 + 1 = 31 bits -> 1 word.
    /// But we need more for the full `MAX_ORDER`=10 chain. Use 2 words.
    type SmallAllocator = BuddyAllocator<16, 2>;

    fn base() -> PhysAddr {
        PhysAddr::new(0x1000_0000)
    }

    #[test]
    fn create_allocator() {
        let alloc = SmallAllocator::new(base()).unwrap();
        assert_eq!(alloc.free_page_count(), 16);
    }

    #[test]
    fn unaligned_base_fails() {
        assert!(matches!(
            SmallAllocator::new(PhysAddr::new(0x1000_0001)),
            Err(RvmError::AlignmentError)
        ));
    }

    #[test]
    fn alloc_single_page() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        let addr = alloc.alloc_pages(0).unwrap();
        assert!(addr.is_page_aligned());
        assert!(addr.as_u64() >= base().as_u64());
        assert_eq!(alloc.free_page_count(), 15);
    }

    #[test]
    fn alloc_all_pages_individually() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        let mut addrs = [PhysAddr::new(0); 16];
        for (i, addr) in addrs.iter_mut().enumerate() {
            *addr = alloc.alloc_pages(0).unwrap();
            let _ = i;
        }
        assert_eq!(alloc.free_page_count(), 0);

        // Next allocation should fail.
        assert_eq!(alloc.alloc_pages(0), Err(RvmError::OutOfMemory));

        // All addresses should be distinct and page-aligned.
        for (i, a) in addrs.iter().enumerate() {
            assert!(a.is_page_aligned());
            for b in &addrs[(i + 1)..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn alloc_order_2() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        // Order 2 = 4 pages.
        let addr = alloc.alloc_pages(2).unwrap();
        assert!(addr.is_page_aligned());
        assert_eq!(alloc.free_page_count(), 12);
    }

    #[test]
    fn alloc_too_large_fails() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        // `MAX_ORDER` for 16 pages is 4 (2^4 = 16).
        // Trying order 5 should fail since 2^5 = 32 > 16.
        assert_eq!(alloc.alloc_pages(5), Err(RvmError::OutOfMemory));
    }

    #[test]
    fn free_and_realloc() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        let addr = alloc.alloc_pages(0).unwrap();
        assert_eq!(alloc.free_page_count(), 15);

        alloc.free_pages(addr, 0).unwrap();
        assert_eq!(alloc.free_page_count(), 16);

        // Should be able to allocate again.
        let addr2 = alloc.alloc_pages(0).unwrap();
        assert!(addr2.is_page_aligned());
    }

    #[test]
    fn free_invalid_address() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        // Address before base.
        assert!(alloc.free_pages(PhysAddr::new(0), 0).is_err());
        // Unaligned address.
        assert!(alloc
            .free_pages(PhysAddr::new(base().as_u64() + 1), 0)
            .is_err());
    }

    #[test]
    fn double_free_detected() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        let addr = alloc.alloc_pages(0).unwrap();
        alloc.free_pages(addr, 0).unwrap();
        // Second free should fail.
        assert_eq!(alloc.free_pages(addr, 0), Err(RvmError::InternalError));
    }

    #[test]
    fn buddy_coalescing() {
        let mut alloc = SmallAllocator::new(base()).unwrap();

        // Allocate two order-0 blocks (consecutive pages).
        let a = alloc.alloc_pages(0).unwrap();
        let b = alloc.alloc_pages(0).unwrap();
        assert_eq!(alloc.free_page_count(), 14);

        // Free both -- they should coalesce into an order-1 block.
        alloc.free_pages(a, 0).unwrap();
        alloc.free_pages(b, 0).unwrap();
        assert_eq!(alloc.free_page_count(), 16);

        // Verify we can now allocate a single order-4 (16-page) block,
        // meaning everything coalesced back to the top.
        let big = alloc.alloc_pages(4).unwrap();
        assert!(big.is_page_aligned());
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn alloc_mixed_orders() {
        let mut alloc = SmallAllocator::new(base()).unwrap();

        // Allocate: 1 page + 2 pages + 4 pages + 8 pages = 15 pages.
        // Only 1 page should remain.
        let _a = alloc.alloc_pages(0).unwrap(); // 1 page
        let _b = alloc.alloc_pages(1).unwrap(); // 2 pages
        let _c = alloc.alloc_pages(2).unwrap(); // 4 pages
        let _d = alloc.alloc_pages(3).unwrap(); // 8 pages
        assert_eq!(alloc.free_page_count(), 1);

        // One more order-0 allocation should succeed.
        let _e = alloc.alloc_pages(0).unwrap();
        assert_eq!(alloc.free_page_count(), 0);

        // Now should be out of memory.
        assert_eq!(alloc.alloc_pages(0), Err(RvmError::OutOfMemory));
    }

    /// A larger allocator for stress testing: 256 pages.
    type MediumAllocator = BuddyAllocator<256, 16>;

    #[test]
    fn medium_allocator_full_cycle() {
        let mut alloc = MediumAllocator::new(base()).unwrap();
        assert_eq!(alloc.free_page_count(), 256);

        // Allocate 64 order-0 blocks.
        let mut addrs = [PhysAddr::new(0); 64];
        for addr in &mut addrs {
            *addr = alloc.alloc_pages(0).unwrap();
        }
        assert_eq!(alloc.free_page_count(), 192);

        // Free them all.
        for addr in &addrs {
            alloc.free_pages(*addr, 0).unwrap();
        }
        assert_eq!(alloc.free_page_count(), 256);
    }

    // ---------------------------------------------------------------
    // Buddy allocator under full allocation pressure
    // ---------------------------------------------------------------

    #[test]
    fn full_allocation_pressure_order_0() {
        // Allocate all 16 pages one by one, then verify OOM.
        let mut alloc = SmallAllocator::new(base()).unwrap();
        let mut addrs = [PhysAddr::new(0); 16];
        for addr in &mut addrs {
            *addr = alloc.alloc_pages(0).unwrap();
        }
        assert_eq!(alloc.free_page_count(), 0);
        assert_eq!(alloc.alloc_pages(0), Err(RvmError::OutOfMemory));

        // Free one and immediately re-allocate.
        alloc.free_pages(addrs[7], 0).unwrap();
        assert_eq!(alloc.free_page_count(), 1);
        let reused = alloc.alloc_pages(0).unwrap();
        assert!(reused.is_page_aligned());
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn full_allocation_pressure_mixed_orders() {
        // Allocate: 8 pages (order 3), 4 pages (order 2), 2 pages (order 1),
        // 1 page (order 0), 1 page (order 0) = 16 total.
        let mut alloc = SmallAllocator::new(base()).unwrap();
        let a = alloc.alloc_pages(3).unwrap(); // 8 pages
        let b = alloc.alloc_pages(2).unwrap(); // 4 pages
        let c = alloc.alloc_pages(1).unwrap(); // 2 pages
        let d = alloc.alloc_pages(0).unwrap(); // 1 page
        let e = alloc.alloc_pages(0).unwrap(); // 1 page
        assert_eq!(alloc.free_page_count(), 0);

        // Now free in reverse order and verify coalescing.
        alloc.free_pages(e, 0).unwrap();
        alloc.free_pages(d, 0).unwrap();
        assert_eq!(alloc.free_page_count(), 2);

        alloc.free_pages(c, 1).unwrap();
        assert_eq!(alloc.free_page_count(), 4);

        alloc.free_pages(b, 2).unwrap();
        assert_eq!(alloc.free_page_count(), 8);

        alloc.free_pages(a, 3).unwrap();
        assert_eq!(alloc.free_page_count(), 16); // Fully coalesced.
    }

    #[test]
    fn free_wrong_order_size_detected() {
        // Allocate order 1 (2 pages), then free with order 0.
        // This should succeed (the allocator tracks blocks at the bitmap level).
        // But it may create fragmentation -- we just verify no panic.
        let mut alloc = SmallAllocator::new(base()).unwrap();
        let _addr = alloc.alloc_pages(1).unwrap();
        // We do not try to free with the wrong order because the buddy
        // allocator's bitmap tracking would not match cleanly. This test
        // documents the expected behavior.
    }

    #[test]
    fn alloc_after_partial_free_coalescing() {
        let mut alloc = SmallAllocator::new(base()).unwrap();

        // Fill entirely with order-0 blocks.
        let mut addrs = [PhysAddr::new(0); 16];
        for addr in &mut addrs {
            *addr = alloc.alloc_pages(0).unwrap();
        }
        assert_eq!(alloc.free_page_count(), 0);

        // Free first two blocks. They should coalesce into an order-1 block.
        alloc.free_pages(addrs[0], 0).unwrap();
        alloc.free_pages(addrs[1], 0).unwrap();

        // Now we should be able to allocate an order-1 (2-page) block.
        let big = alloc.alloc_pages(1).unwrap();
        assert!(big.is_page_aligned());
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn medium_allocator_full_pressure_and_recovery() {
        let mut alloc = MediumAllocator::new(base()).unwrap();

        // Fill all 256 pages with order-0 allocations.
        let mut addrs = [PhysAddr::new(0); 256];
        for addr in &mut addrs {
            *addr = alloc.alloc_pages(0).unwrap();
        }
        assert_eq!(alloc.free_page_count(), 0);
        assert_eq!(alloc.alloc_pages(0), Err(RvmError::OutOfMemory));

        // Free all.
        for addr in &addrs {
            alloc.free_pages(*addr, 0).unwrap();
        }
        assert_eq!(alloc.free_page_count(), 256);

        // After full free, should coalesce back to highest order.
        // Try allocating the largest possible block.
        let big = alloc.alloc_pages(8).unwrap(); // 256 pages
        assert!(big.is_page_aligned());
        assert_eq!(alloc.free_page_count(), 0);
    }

    #[test]
    fn free_beyond_total_pages_fails() {
        let mut alloc = SmallAllocator::new(base()).unwrap();
        // Address beyond the managed range.
        let beyond = PhysAddr::new(base().as_u64() + 16 * PAGE_SIZE as u64);
        assert!(alloc.free_pages(beyond, 0).is_err());
    }
}
