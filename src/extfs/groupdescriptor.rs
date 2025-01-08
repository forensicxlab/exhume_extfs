#[derive(Debug)]
pub struct GroupDescriptor {
    /// Full 64-bit block number for the block bitmap.
    pub bg_block_bitmap: u64,
    /// Full 64-bit block number for the inode bitmap.
    pub bg_inode_bitmap: u64,
    /// Full 64-bit block number for the inode table.
    pub bg_inode_table: u64,

    /// Lower 16 bits of free blocks count (plus optional upper bits).
    pub bg_free_blocks_count: u32,
    /// Lower 16 bits of free inodes count (plus optional upper bits).
    pub bg_free_inodes_count: u32,
    /// Lower 16 bits of used directories count (plus optional upper bits).
    pub bg_used_dirs_count: u32,

    /// Flags (lower 16 bits from older layout).
    pub bg_flags: u16,
}

impl GroupDescriptor {
    /// Parse a group descriptor from a raw slice.
    ///
    /// `data` must contain at least 32 bytes. If `has_64bit` is `true`,
    /// then `data` must contain at least 64 bytes (the extended area).
    pub fn from_bytes(data: &[u8], has_64bit: bool) -> Self {
        // Helpers for reading little-endian values from the given slice.
        let le_u16 = |offset: usize| -> u16 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
        };
        let le_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };

        // -------------------------------------------------------------------
        // Parse the "older" 32-byte layout (common to both 32-bit & 64-bit).
        // -------------------------------------------------------------------
        let bg_block_bitmap_lo = le_u32(0x00);
        let bg_inode_bitmap_lo = le_u32(0x04);
        let bg_inode_table_lo = le_u32(0x08);

        let bg_free_blocks_count_lo = le_u16(0x0C);
        let bg_free_inodes_count_lo = le_u16(0x0E);
        let bg_used_dirs_count_lo = le_u16(0x10);

        let bg_flags = le_u16(0x12);

        // -------------------------------------------------------------------
        // If 64-bit feature is active, parse the high parts.
        // -------------------------------------------------------------------
        let (bg_block_bitmap_hi, bg_inode_bitmap_hi, bg_inode_table_hi) = if has_64bit {
            // The hi fields start at offset 0x20 in the official ext4 doc
            // (struct ext4_group_desc in <linux/ext4.h>).
            let bb_hi = le_u32(0x20); // bg_block_bitmap_hi
            let ib_hi = le_u32(0x24); // bg_inode_bitmap_hi
            let it_hi = le_u32(0x28); // bg_inode_table_hi
            (bb_hi, ib_hi, it_hi)
        } else {
            (0, 0, 0)
        };

        let (bg_free_blocks_count_hi, bg_free_inodes_count_hi, bg_used_dirs_count_hi) = if has_64bit
        {
            // These are 16-bit fields immediately after the block/inode table hi.
            let fbc_hi = le_u16(0x2C);
            let fic_hi = le_u16(0x2E);
            let udc_hi = le_u16(0x30);
            (fbc_hi, fic_hi, udc_hi)
        } else {
            (0, 0, 0)
        };

        // Combine lo + hi fields into the final 64-bit or 32-bit values.
        let bg_block_bitmap = (bg_block_bitmap_hi as u64) << 32 | (bg_block_bitmap_lo as u64);
        let bg_inode_bitmap = (bg_inode_bitmap_hi as u64) << 32 | (bg_inode_bitmap_lo as u64);
        let bg_inode_table = (bg_inode_table_hi as u64) << 32 | (bg_inode_table_lo as u64);

        // For counts (which are 32 bits total in 64BIT mode) we combine them:
        let bg_free_blocks_count =
            ((bg_free_blocks_count_hi as u32) << 16) | (bg_free_blocks_count_lo as u32);
        let bg_free_inodes_count =
            ((bg_free_inodes_count_hi as u32) << 16) | (bg_free_inodes_count_lo as u32);
        let bg_used_dirs_count =
            ((bg_used_dirs_count_hi as u32) << 16) | (bg_used_dirs_count_lo as u32);

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

    pub fn bg_inode_table(&self) -> u64 {
        self.bg_inode_table
    }
}
