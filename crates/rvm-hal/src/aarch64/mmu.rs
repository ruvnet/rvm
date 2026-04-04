//! Stage-2 page table management for AArch64.
//!
//! Implements 4KB-granule, 2-level stage-2 translation for QEMU virt:
//! - Level 1: 512 entries x 1GB blocks (or table descriptors to L2)
//! - Level 2: 512 entries x 2MB blocks
//!
//! The IPA space is 40 bits (1 TB), starting at level 1 (SL0=1 in VTCR_EL2).

use rvm_types::{GuestPhysAddr, PhysAddr, RvmResult, RvmError};

/// Page size: 4 KB.
pub const PAGE_SIZE: usize = 4096;

/// Number of entries per page table level (4KB / 8 bytes).
const ENTRIES_PER_TABLE: usize = 512;

/// Size of a level-1 block entry: 1 GB.
#[allow(dead_code)]
const L1_BLOCK_SIZE: u64 = 1 << 30;

/// Size of a level-2 block entry: 2 MB.
const L2_BLOCK_SIZE: u64 = 1 << 21;

// Stage-2 descriptor bits
mod s2_desc {
    /// Valid descriptor.
    pub const VALID: u64 = 1 << 0;
    /// Table descriptor (vs block) at level 1.
    pub const TABLE: u64 = 1 << 1;
    /// Block descriptor at level 1/2 (bit 1 = 0 for block).
    /// Stage-2 block: valid=1, bit1=0.
    // (A block descriptor has bit[1]=0 and bit[0]=1.)

    /// Access flag.
    pub const AF: u64 = 1 << 10;

    /// Stage-2 memory attribute index shift (MemAttr[3:2] = bits [5:4]).
    pub const MEM_ATTR_SHIFT: u32 = 2;

    /// Stage-2 shareability field shift (SH[1:0] = bits [9:8]).
    pub const SH_SHIFT: u32 = 8;

    /// Normal memory, outer write-back / inner write-back (MemAttr = 0xF).
    pub const MEM_ATTR_NORMAL_WB: u64 = 0xF << MEM_ATTR_SHIFT;

    /// Device-nGnRnE memory (MemAttr = 0x0).
    pub const MEM_ATTR_DEVICE: u64 = 0x0 << MEM_ATTR_SHIFT;

    /// Inner Shareable.
    pub const SH_INNER: u64 = 3 << SH_SHIFT;

    /// Outer Shareable.
    pub const SH_OUTER: u64 = 2 << SH_SHIFT;

    /// Stage-2 S2AP (access permission) shift.
    pub const S2AP_SHIFT: u32 = 6;

    /// S2AP: read-write.
    pub const S2AP_RW: u64 = 3 << S2AP_SHIFT;

    /// S2AP: read-only.
    #[allow(dead_code)]
    pub const S2AP_RO: u64 = 1 << S2AP_SHIFT;

    /// Execute-never for EL1.
    pub const XN: u64 = 1 << 54;
}

/// Stage-2 page table for a single guest.
///
/// Level 1 table with 512 entries covering up to 512 GB of IPA space.
/// Each entry is either invalid, a 1 GB block, or a table pointer to
/// a level-2 table (stored in `l2_tables`).
///
/// This structure must be 4096-byte aligned for use with VTTBR_EL2.
#[repr(C, align(4096))]
pub struct Stage2PageTable {
    /// Level 1 table: 512 entries, each covering 1 GB.
    l1_table: [u64; ENTRIES_PER_TABLE],
    /// Pool of level-2 tables. Each covers 1 GB via 512 x 2MB blocks.
    /// We pre-allocate a small pool; index 0..next_l2 are in use.
    l2_tables: [[u64; ENTRIES_PER_TABLE]; Self::MAX_L2_TABLES],
    /// Number of L2 tables allocated so far.
    next_l2: usize,
}

impl Stage2PageTable {
    /// Maximum number of level-2 tables we can allocate.
    /// 4 tables cover 4 GB of IPA space with 2 MB granularity.
    const MAX_L2_TABLES: usize = 4;

    /// Create a new, empty stage-2 page table (all entries invalid).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            l1_table: [0; ENTRIES_PER_TABLE],
            l2_tables: [[0; ENTRIES_PER_TABLE]; Self::MAX_L2_TABLES],
            next_l2: 0,
        }
    }

    /// Return the physical address of the L1 table for VTTBR_EL2.
    ///
    /// # Safety
    ///
    /// The returned address is only valid while `self` is not moved.
    /// The caller must ensure the page table remains pinned in memory
    /// while it is installed in VTTBR_EL2.
    pub fn l1_base_addr(&self) -> u64 {
        self.l1_table.as_ptr() as u64
    }

    /// Map a 2 MB block at the given IPA to the given PA.
    ///
    /// `attrs` provides the raw stage-2 descriptor attributes (MemAttr,
    /// SH, S2AP, XN). The caller should use helper methods like
    /// [`map_ram_2mb`] or [`map_device_2mb`] instead of calling this
    /// directly.
    ///
    /// # Errors
    ///
    /// Returns `RvmError::MemoryExhausted` if no L2 table slots remain.
    /// Returns `RvmError::InternalError` if addresses are misaligned.
    pub fn map_2mb_block(&mut self, ipa: u64, pa: u64, attrs: u64) -> RvmResult<()> {
        if ipa & (L2_BLOCK_SIZE - 1) != 0 || pa & (L2_BLOCK_SIZE - 1) != 0 {
            return Err(RvmError::InternalError);
        }

        let l1_index = ((ipa >> 30) & 0x1FF) as usize;
        let l2_index = ((ipa >> 21) & 0x1FF) as usize;

        // Ensure L1 entry points to an L2 table.
        if self.l1_table[l1_index] & s2_desc::VALID == 0 {
            self.alloc_l2_for(l1_index)?;
        }

        let l2_idx = self.l1_to_l2_index(l1_index);
        // Build block descriptor: PA | attrs | AF | VALID (bit[1]=0 for block).
        let descriptor = (pa & 0x0000_FFFF_FFE0_0000) | attrs | s2_desc::AF | s2_desc::VALID;
        self.l2_tables[l2_idx][l2_index] = descriptor;

        Ok(())
    }

    /// Map a 2 MB block of normal RAM (write-back, inner shareable, RW).
    ///
    /// # Errors
    ///
    /// Propagates errors from [`map_2mb_block`].
    pub fn map_ram_2mb(&mut self, ipa: u64, pa: u64) -> RvmResult<()> {
        let attrs = s2_desc::MEM_ATTR_NORMAL_WB | s2_desc::SH_INNER | s2_desc::S2AP_RW;
        self.map_2mb_block(ipa, pa, attrs)
    }

    /// Map a 2 MB block of device memory (nGnRnE, outer shareable, RW, XN).
    ///
    /// # Errors
    ///
    /// Propagates errors from [`map_2mb_block`].
    pub fn map_device_2mb(&mut self, ipa: u64, pa: u64) -> RvmResult<()> {
        let attrs =
            s2_desc::MEM_ATTR_DEVICE | s2_desc::SH_OUTER | s2_desc::S2AP_RW | s2_desc::XN;
        self.map_2mb_block(ipa, pa, attrs)
    }

    /// Identity-map RAM from IPA 0 up to `size` bytes (2 MB aligned).
    ///
    /// # Errors
    ///
    /// Returns an error if `size` is not 2 MB aligned or if L2 tables
    /// are exhausted.
    pub fn identity_map_ram(&mut self, size: u64) -> RvmResult<()> {
        if size & (L2_BLOCK_SIZE - 1) != 0 {
            return Err(RvmError::InternalError);
        }

        let mut addr: u64 = 0;
        while addr < size {
            self.map_ram_2mb(addr, addr)?;
            addr += L2_BLOCK_SIZE;
        }
        Ok(())
    }

    /// Identity-map the QEMU virt device region.
    ///
    /// Maps the standard QEMU virt MMIO ranges:
    /// - 0x0800_0000 - 0x09FF_FFFF (GIC, UART, RTC, etc.)
    ///
    /// The device region is mapped as 2 MB blocks with device-nGnRnE
    /// attributes.
    ///
    /// # Errors
    ///
    /// Returns an error if L2 tables are exhausted.
    pub fn identity_map_devices(&mut self) -> RvmResult<()> {
        // QEMU virt device region: 0x0800_0000 .. 0x0A00_0000 (32 MB)
        // Mapped as 16 x 2MB blocks.
        let base: u64 = 0x0800_0000;
        let end: u64 = 0x0A00_0000;
        let mut addr = base;
        while addr < end {
            self.map_device_2mb(addr, addr)?;
            addr += L2_BLOCK_SIZE;
        }
        Ok(())
    }

    /// Allocate an L2 table for the given L1 index.
    fn alloc_l2_for(&mut self, l1_index: usize) -> RvmResult<()> {
        if self.next_l2 >= Self::MAX_L2_TABLES {
            return Err(RvmError::OutOfMemory);
        }

        let l2_idx = self.next_l2;
        self.next_l2 += 1;

        // Zero the L2 table.
        self.l2_tables[l2_idx] = [0; ENTRIES_PER_TABLE];

        // Build L1 table descriptor pointing to the L2 table.
        let l2_addr = self.l2_tables[l2_idx].as_ptr() as u64;
        // Table descriptor: addr | TABLE(1) | VALID(1).
        self.l1_table[l1_index] = (l2_addr & 0x0000_FFFF_FFFF_F000)
            | s2_desc::TABLE
            | s2_desc::VALID
            | (l2_idx as u64) << 56; // Stash index in software bits [63:56]

        Ok(())
    }

    /// Look up which L2 table index is used for a given L1 index.
    fn l1_to_l2_index(&self, l1_index: usize) -> usize {
        // The L2 index is stashed in bits [63:56] of the L1 descriptor.
        ((self.l1_table[l1_index] >> 56) & 0xFF) as usize
    }
}

/// AArch64 stage-2 MMU operations implementing the HAL `MmuOps` trait.
pub struct Aarch64Mmu {
    /// The stage-2 page table for this MMU instance.
    page_table: Stage2PageTable,
    /// Whether the MMU has been installed (VTTBR_EL2 written).
    installed: bool,
}

impl Aarch64Mmu {
    /// Create a new AArch64 MMU with empty page tables.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            page_table: Stage2PageTable::new(),
            installed: false,
        }
    }

    /// Return a mutable reference to the underlying page table.
    pub fn page_table_mut(&mut self) -> &mut Stage2PageTable {
        &mut self.page_table
    }

    /// Return a reference to the underlying page table.
    pub fn page_table(&self) -> &Stage2PageTable {
        &self.page_table
    }

    /// Install the page table into VTTBR_EL2 and enable stage-2 translation.
    ///
    /// # Safety
    ///
    /// The page table must remain pinned in memory for the lifetime of
    /// the MMU. This must be called at EL2.
    pub unsafe fn install(&mut self) {
        let base = self.page_table.l1_base_addr();

        // SAFETY: Caller guarantees EL2 and pinned page table.
        // These functions contain their own internal unsafe blocks for
        // register access; we call them from an unsafe fn context.
        super::boot::configure_vtcr_el2();
        super::boot::set_vttbr_el2(base);
        super::boot::invalidate_stage2_tlb();
        self.installed = true;
    }
}

impl crate::MmuOps for Aarch64Mmu {
    fn map_page(&mut self, guest: GuestPhysAddr, host: PhysAddr) -> RvmResult<()> {
        // Stage-2 maps 2MB blocks. Round down to 2MB alignment.
        let ipa = guest.as_u64() & !(L2_BLOCK_SIZE - 1);
        let pa = host.as_u64() & !(L2_BLOCK_SIZE - 1);
        self.page_table.map_ram_2mb(ipa, pa)
    }

    fn unmap_page(&mut self, guest: GuestPhysAddr) -> RvmResult<()> {
        let l1_index = ((guest.as_u64() >> 30) & 0x1FF) as usize;
        let l2_index = ((guest.as_u64() >> 21) & 0x1FF) as usize;

        if self.page_table.l1_table[l1_index] & s2_desc::VALID == 0 {
            return Err(RvmError::InternalError);
        }

        let l2_idx = self.page_table.l1_to_l2_index(l1_index);
        if self.page_table.l2_tables[l2_idx][l2_index] & s2_desc::VALID == 0 {
            return Err(RvmError::InternalError);
        }

        self.page_table.l2_tables[l2_idx][l2_index] = 0;
        Ok(())
    }

    fn translate(&self, guest: GuestPhysAddr) -> RvmResult<PhysAddr> {
        let l1_index = ((guest.as_u64() >> 30) & 0x1FF) as usize;
        let l2_index = ((guest.as_u64() >> 21) & 0x1FF) as usize;

        if self.page_table.l1_table[l1_index] & s2_desc::VALID == 0 {
            return Err(RvmError::InternalError);
        }

        let l2_idx = self.page_table.l1_to_l2_index(l1_index);
        let entry = self.page_table.l2_tables[l2_idx][l2_index];
        if entry & s2_desc::VALID == 0 {
            return Err(RvmError::InternalError);
        }

        // Extract PA from block descriptor bits [47:21].
        let block_pa = entry & 0x0000_FFFF_FFE0_0000;
        let offset = guest.as_u64() & (L2_BLOCK_SIZE - 1);
        Ok(PhysAddr::new(block_pa | offset))
    }

    fn flush_tlb(&mut self, _guest: GuestPhysAddr, _page_count: usize) -> RvmResult<()> {
        // For simplicity, flush all stage-2 TLB entries.
        // A production implementation would use TLBI by IPA.
        // invalidate_stage2_tlb() contains its own internal unsafe block.
        super::boot::invalidate_stage2_tlb();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage2_page_table_new() {
        let pt = Stage2PageTable::new();
        assert_eq!(pt.next_l2, 0);
        for entry in &pt.l1_table {
            assert_eq!(*entry, 0);
        }
    }

    #[test]
    fn test_l2_block_size() {
        assert_eq!(L2_BLOCK_SIZE, 2 * 1024 * 1024); // 2 MB
    }

    #[test]
    fn test_l1_block_size() {
        assert_eq!(L1_BLOCK_SIZE, 1024 * 1024 * 1024); // 1 GB
    }

    #[test]
    fn test_entries_per_table() {
        assert_eq!(ENTRIES_PER_TABLE, 512);
    }

    #[test]
    fn test_s2_descriptor_bits() {
        assert_eq!(s2_desc::VALID, 1);
        assert_eq!(s2_desc::TABLE, 2);
        assert_eq!(s2_desc::AF, 1 << 10);
    }

    #[test]
    fn test_stage2_alignment() {
        // Verify that Stage2PageTable is 4096-byte aligned.
        assert_eq!(
            core::mem::align_of::<Stage2PageTable>(),
            4096,
        );
    }

    #[test]
    fn test_aarch64_mmu_new() {
        let mmu = Aarch64Mmu::new();
        assert!(!mmu.installed);
    }
}
