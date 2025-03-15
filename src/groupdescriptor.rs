use serde_json::{json, Value};

#[derive(Debug)]
pub struct GroupDescriptor {
    // Full 64-bit block number for the block bitmap.
    bg_block_bitmap: u64,
    // Full 64-bit block number for the inode bitmap.
    bg_inode_bitmap: u64,
    // Full 64-bit block number for the inode table.
    bg_inode_table: u64,
    // Lower 16 bits of free blocks count (plus optional upper bits).
    bg_free_blocks_count: u32,
    // Lower 16 bits of free inodes count (plus optional upper bits).
    bg_free_inodes_count: u32,
    // Lower 16 bits of used directories count (plus optional upper bits).
    bg_used_dirs_count: u32,
    // Flags (lower 16 bits from older layout).
    bg_flags: u16,
}

impl GroupDescriptor {
    /// Parses a group descriptor from a raw byte slice.
    ///
    /// `data` must contain at least 32 bytes. If `has_64bit` is `true`,
    /// then `data` must contain at least 64 bytes for the extended area
    /// necessary for 64-bit values.
    pub fn from_bytes(data: &[u8], has_64bit: bool) -> Self {
        // Helper closure for reading little-endian 16-bit values from the slice.
        let le_u16 = |offset: usize| -> u16 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
        };
        // Helper closure for reading little-endian 32-bit values from the slice.
        let le_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };

        // -------------------------------------------------------------------
        // Parse the "older" 32-byte layout common to both 32-bit & 64-bit.
        // -------------------------------------------------------------------
        let bg_block_bitmap_lo = le_u32(0x00); // Lower 32 bits of block bitmap.
        let bg_inode_bitmap_lo = le_u32(0x04); // Lower 32 bits of inode bitmap.
        let bg_inode_table_lo = le_u32(0x08); // Lower 32 bits of inode table.

        let bg_free_blocks_count_lo = le_u16(0x0C); // Lower 16 bits of free blocks count.
        let bg_free_inodes_count_lo = le_u16(0x0E); // Lower 16 bits of free inodes count.
        let bg_used_dirs_count_lo = le_u16(0x10); // Lower 16 bits of used directories count.

        let bg_flags = le_u16(0x12); // 16-bit flags indicator.

        // -------------------------------------------------------------------
        // Conditional parsing for the 64-bit extension if the feature is active.
        // -------------------------------------------------------------------
        let (bg_block_bitmap_hi, bg_inode_bitmap_hi, bg_inode_table_hi) = if has_64bit {
            // Offsets for high part of the fields as per ext4 documentation.
            let bb_hi = le_u32(0x20); // High 32 bits for block bitmap.
            let ib_hi = le_u32(0x24); // High 32 bits for inode bitmap.
            let it_hi = le_u32(0x28); // High 32 bits for inode table.
            (bb_hi, ib_hi, it_hi)
        } else {
            // Default to zero if 64-bit feature is not active.
            (0, 0, 0)
        };

        let (bg_free_blocks_count_hi, bg_free_inodes_count_hi, bg_used_dirs_count_hi) = if has_64bit
        {
            // 16-bit high part fields following the 32-bit high sections.
            let fbc_hi = le_u16(0x2C); // High 16 bits for free blocks count.
            let fic_hi = le_u16(0x2E); // High 16 bits for free inodes count.
            let udc_hi = le_u16(0x30); // High 16 bits for used directories count.
            (fbc_hi, fic_hi, udc_hi)
        } else {
            // Default to zero if 64-bit feature is not active.
            (0, 0, 0)
        };

        // Combine low and high parts to form final 64-bit or 32-bit values.
        let bg_block_bitmap = (bg_block_bitmap_hi as u64) << 32 | (bg_block_bitmap_lo as u64);
        let bg_inode_bitmap = (bg_inode_bitmap_hi as u64) << 32 | (bg_inode_bitmap_lo as u64);
        let bg_inode_table = (bg_inode_table_hi as u64) << 32 | (bg_inode_table_lo as u64);

        // Combine the low and high parts for 32-bit counts in 64BIT mode.
        let bg_free_blocks_count =
            ((bg_free_blocks_count_hi as u32) << 16) | (bg_free_blocks_count_lo as u32);
        let bg_free_inodes_count =
            ((bg_free_inodes_count_hi as u32) << 16) | (bg_free_inodes_count_lo as u32);
        let bg_used_dirs_count =
            ((bg_used_dirs_count_hi as u32) << 16) | (bg_used_dirs_count_lo as u32);

        // Return the GroupDescriptor built from parsed values.
        GroupDescriptor {
            bg_block_bitmap,
            bg_inode_bitmap,
            bg_inode_table,
            bg_free_blocks_count,
            bg_free_inodes_count,
            bg_used_dirs_count,
            bg_flags,
        }
    }

    /// Returns the 64-bit block number for the inode table.
    pub fn bg_inode_table(&self) -> u64 {
        self.bg_inode_table
    }

    /// Converts the group descriptor into a JSON object for external use.
    ///
    /// The 'to_json' method is used by external modules (e.g., Thanatology)
    /// to serialize the GroupDescriptor structure for JSON-based applications.
    pub fn to_json(&self) -> Value {
        json!({
            "block_bitmap": self.bg_block_bitmap,
            "inode_bitmap": self.bg_inode_bitmap,
            "inode_table": self.bg_inode_table,
            "free_blocks_count": self.bg_free_blocks_count,
            "free_inodes_count": self.bg_free_inodes_count,
            "used_dirs_count": self.bg_used_dirs_count,
            "flags": self.bg_flags,
        })
    }
}
