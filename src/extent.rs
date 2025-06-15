//! Extent tree structures for **ext4**.

#[derive(Debug)]
/// A structure representing an Extent Header block in an ext4 filesystem.
pub struct ExtentHeader {
    /// The magic number for the extent header, should be 0xF30A for ext4.
    pub eh_magic: u16,
    /// The number of valid entries.
    pub eh_entries: u16,
    /// The maximum number of entries that can be stored in the extent.
    pub eh_max: u16,
    /// The depth of the extent tree.
    pub eh_depth: u16,
}

impl ExtentHeader {
    /// Parse an ['ExtentHeader'] from *exactly* the first 8 bytes of a node.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            eh_magic: u16::from_le_bytes(data[0..2].try_into().unwrap()),
            eh_entries: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            eh_max: u16::from_le_bytes(data[4..6].try_into().unwrap()),
            eh_depth: u16::from_le_bytes(data[6..8].try_into().unwrap()),
        }
    }

    /// 'true' when 'eh_depth == 0'.
    #[inline]
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        self.eh_depth == 0
    }

    /// 'true' if 'eh_magic == 0xF30A'.
    #[inline]
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.eh_magic == 0xF30A
    }
}

#[derive(Debug)]
/// Leaf‐node entry describing a contiguous range of blocks.
pub struct ExtentLeaf {
    /// First logical block covered by this extent.
    pub ee_block: u32,
    /// Length in blocks (`ee_len == 0` means 65 536).
    pub ee_len: u16,
    /// First *physical* block on disk.
    pub ee_start: usize,
}

impl ExtentLeaf {
    /// Parse an ['ExtentLeaf'] from 12 bytes.
    pub fn from_bytes(data: &[u8]) -> ExtentLeaf {
        let ee_start_hi = u16::from_le_bytes(data[0x6..0x8].try_into().unwrap()) as u32;
        let ee_start_lo = u32::from_le_bytes(data[0x8..0xC].try_into().unwrap());
        ExtentLeaf {
            ee_block: u32::from_le_bytes(data[0x0..0x4].try_into().unwrap()),
            ee_len: u16::from_le_bytes(data[0x4..0x6].try_into().unwrap()),
            ee_start: (ee_start_lo | (ee_start_hi << 16)) as usize,
        }
    }
}

#[derive(Debug)]
/// A structure representing an Extent Index in an ext4 filesystem.
pub struct ExtentIndex {
    /// The block number in the index.
    pub ei_block: u32,
    /// Lower 32 bits of the physical block number of the extent this index points to.
    pub ei_leaf_lo: u32,
    /// Upper 16 bits of the physical block number of the extent this index points to.
    pub ei_leaf_hi: u16,
    /// Unused space in the structure.
    pub ei_unused: u16,
}

impl ExtentIndex {
    /// Creates an ExtentIndex from a slice of bytes.
    pub fn from_bytes(data: &[u8]) -> Self {
        let ei_block = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let ei_leaf_lo = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let ei_leaf_hi = u16::from_le_bytes(data[8..10].try_into().unwrap());
        let ei_unused = u16::from_le_bytes(data[10..12].try_into().unwrap());
        Self {
            ei_block,
            ei_leaf_lo,
            ei_leaf_hi,
            ei_unused,
        }
    }

    /// Combines the high and low parts of the leaf block number into a full 64-bit address.
    ///
    /// # Returns
    ///
    /// The full 64-bit physical block number that the index points to.
    pub fn leaf(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | (self.ei_leaf_lo as u64)
    }
}
