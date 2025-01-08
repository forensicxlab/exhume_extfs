/// Reference: https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html

#[derive(Debug)]
pub struct Inode {
    i_mode: u16,
    i_uid: u16,
    i_size_lo: u32,
    i_atime: u32,
    i_ctime: u32,
    i_mtime: u32,
    i_dtime: u32,
    i_gid: u16,
    i_links_count: u16,
    i_blocks_lo: u32,
    i_flags: u32,
    l_i_version: u32,
    i_block: [u32; 15],
    i_generation: u32,
    i_file_acl_lo: u32,
    i_size_high: u32,
    i_obso_faddr: u32,
    l_i_blocks_high: u16,
    l_i_file_acl_high: u16,
    l_i_uid_high: u16,
    l_i_gid_high: u16,
    l_i_checksum_lo: u16,
    l_i_reserved: u16,
    i_extra_isize: u16,
    i_checksum_hi: u16,
    i_ctime_extra: u32,
    i_mtime_extra: u32,
    i_atime_extra: u32,
    i_crtime: u32,
    i_crtime_extra: u32,
    i_version_hi: u32,
    i_projid: u32,
}

impl Inode {
    /// Parse an ext4-like inode from a raw byte slice.
    ///
    /// Typically, `data` must be at least 128 or 256 bytes, depending on the
    /// inode size configured in the superblock.
    pub fn from_bytes(data: &[u8], inode_size: u64) -> Self {
        let le_u16 = |offset: usize| -> u16 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
        };
        let le_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };

        // Always parse the first 128 bytes
        // (the "classic" inode fields).
        let i_mode = le_u16(0x00);
        let i_uid = le_u16(0x02);
        let i_size_lo = le_u32(0x04);
        let i_atime = le_u32(0x08);
        let i_ctime = le_u32(0x0C);
        let i_mtime = le_u32(0x10);
        let i_dtime = le_u32(0x14);
        let i_gid = le_u16(0x18);
        let i_links_cnt = le_u16(0x1A);
        let i_blocks_lo = le_u32(0x1C);
        let i_flags = le_u32(0x20);
        let l_i_version = le_u32(0x24);

        let mut i_block = [0u32; 15];
        for i in 0..15 {
            i_block[i] = le_u32(0x28 + i * 4);
        }

        // Some fields exist after offset 128 only if inode_size >= 256 (ext4)
        // We'll define defaults if they aren't present
        let i_generation = if inode_size >= 256 { le_u32(0x64) } else { 0 };
        let i_file_acl_lo = if inode_size >= 256 { le_u32(0x68) } else { 0 };
        let i_size_high = if inode_size >= 256 { le_u32(0x6C) } else { 0 };
        let i_obso_faddr = if inode_size >= 256 { le_u32(0x70) } else { 0 };
        let l_i_blocks_high = if inode_size >= 256 { le_u16(0x74) } else { 0 };
        let l_i_file_acl_high = if inode_size >= 256 { le_u16(0x76) } else { 0 };
        let l_i_uid_high = if inode_size >= 256 { le_u16(0x78) } else { 0 };
        let l_i_gid_high = if inode_size >= 256 { le_u16(0x7A) } else { 0 };
        let l_i_checksum_lo = if inode_size >= 256 { le_u16(0x7C) } else { 0 };
        let l_i_reserved = if inode_size >= 256 { le_u16(0x7E) } else { 0 };
        let i_extra_isize = if inode_size >= 256 { le_u16(0x80) } else { 0 };
        let i_checksum_hi = if inode_size >= 256 { le_u16(0x82) } else { 0 };
        let i_ctime_extra = if inode_size >= 256 { le_u32(0x84) } else { 0 };
        let i_mtime_extra = if inode_size >= 256 { le_u32(0x88) } else { 0 };
        let i_atime_extra = if inode_size >= 256 { le_u32(0x8C) } else { 0 };
        let i_crtime = if inode_size >= 256 { le_u32(0x90) } else { 0 };
        let i_crtime_extra = if inode_size >= 256 { le_u32(0x94) } else { 0 };
        let i_version_hi = if inode_size >= 256 { le_u32(0x98) } else { 0 };
        let i_projid = if inode_size >= 256 { le_u32(0x9C) } else { 0 };

        // Construct the inode.
        Inode {
            i_mode,
            i_uid,
            i_size_lo,
            i_atime,
            i_ctime,
            i_mtime,
            i_dtime,
            i_gid,
            i_links_count: i_links_cnt,
            i_blocks_lo,
            i_flags,
            l_i_version,
            i_block,
            i_generation,
            i_file_acl_lo,
            i_size_high,
            i_obso_faddr,
            l_i_blocks_high,
            l_i_file_acl_high,
            l_i_uid_high,
            l_i_gid_high,
            l_i_checksum_lo,
            l_i_reserved,
            i_extra_isize,
            i_checksum_hi,
            i_ctime_extra,
            i_mtime_extra,
            i_atime_extra,
            i_crtime,
            i_crtime_extra,
            i_version_hi,
            i_projid,
        }
    }

    /// Returns the full 64-bit size of the file by combining `i_size_lo` and
    /// `i_size_high`.
    pub fn size(&self) -> u64 {
        ((self.i_size_high as u64) << 32) | (self.i_size_lo as u64)
    }

    /// Check if this inode is a directory (S_IFDIR).
    ///
    /// Note: In Linux, the directory bit is 0o40000 (or `S_IFDIR` = 0x4000 in hex).
    pub fn is_dir(&self) -> bool {
        (self.i_mode & 0o170000) == 0o040000
    }

    /// Check if this inode is a regular file (S_IFREG).
    ///
    /// Note: In Linux, the regular file bit is 0o100000 (or `S_IFREG` = 0x8000 in hex).
    pub fn is_regular_file(&self) -> bool {
        (self.i_mode & 0o170000) == 0o100000
    }

    /// Check if this inode is a symlink (S_IFLNK).
    ///
    /// Note: In Linux, the symlink bit is 0o120000 (or `S_IFLNK` = 0xA000 in hex).
    pub fn is_symlink(&self) -> bool {
        (self.i_mode & 0o170000) == 0o120000
    }

    /// Return the block pointers array. These are typically used to find
    /// the data blocks (or indirect pointer blocks, etc.).
    pub fn block_pointers(&self) -> &[u32; 15] {
        &self.i_block
    }

    /// Combined 32-bit block count (`i_blocks_lo` + `l_i_blocks_high`)
    /// This is normally the total number of 512-byte *segments* (for ext2/3/4),
    pub fn block_count(&self) -> u64 {
        ((self.l_i_blocks_high as u64) << 32) | (self.i_blocks_lo as u64)
    }

    /// Return the effective UID, combining low/high bits. (This matters
    /// only if the UID doesn't fit in 16 bits.)
    pub fn uid(&self) -> u32 {
        ((self.l_i_uid_high as u32) << 16) | (self.i_uid as u32)
    }

    /// Return the effective GID, combining low/high bits.
    pub fn gid(&self) -> u32 {
        ((self.l_i_gid_high as u32) << 16) | (self.i_gid as u32)
    }
}
