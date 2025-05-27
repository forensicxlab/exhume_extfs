/// Reference: https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html
use chrono::{TimeZone, Utc};
use prettytable::{Cell, Row, Table};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const EXT4_NSEC_MASK: u32 = 0xFFFFFFFC;

#[derive(Debug, Serialize, Deserialize)]
pub struct Inode {
    pub i_num: u64,
    pub i_mode: u16,
    pub i_uid: u16,
    pub i_size_lo: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    pub i_atime_h: String,
    pub i_ctime_h: String,
    pub i_mtime_h: String,
    pub i_dtime_h: String,
    pub i_gid: u16,
    pub i_links_count: u16,
    pub i_blocks_lo: u32,
    pub i_flags: u32,
    pub i_block: [u32; 15],
    pub i_generation: u32,
    pub i_file_acl_lo: u32,
    pub i_size_high: u32,
    pub l_i_blocks_high: u16,
    pub l_i_file_acl_high: u16,
    pub l_i_uid_high: u16,
    pub l_i_gid_high: u16,
    pub l_i_checksum_lo: u16,
    pub i_extra_isize: u16,
    pub i_checksum_hi: u16,
    pub i_ctime_extra: u32,
    pub i_mtime_extra: u32,
    pub i_atime_extra: u32,
    pub i_crtime: u32,
    pub i_crtime_extra: u32,
    pub i_crtime_h: String,
    pub i_projid: u32,
}

/// Convert an ext-mode (includes file-type bits) into the familiar
/// 10-character string used by `ls -l`, e.g. "-rw-r--r--".
pub fn mode_to_string(mode: u16) -> String {
    const S_IFMT: u16 = 0o170000;
    const S_IFSOCK: u16 = 0o140000;
    const S_IFLNK: u16 = 0o120000;
    const S_IFREG: u16 = 0o100000;
    const S_IFBLK: u16 = 0o060000;
    const S_IFDIR: u16 = 0o040000;
    const S_IFCHR: u16 = 0o020000;
    const S_IFIFO: u16 = 0o010000;

    const S_ISUID: u16 = 0o4000;
    const S_ISGID: u16 = 0o2000;
    const S_ISVTX: u16 = 0o1000;

    let file_ch = match mode & S_IFMT {
        S_IFSOCK => 's',
        S_IFLNK => 'l',
        S_IFREG => '-',
        S_IFBLK => 'b',
        S_IFDIR => 'd',
        S_IFCHR => 'c',
        S_IFIFO => 'p',
        _ => '?',
    };

    let mut buf = [b'-'; 9];

    // user
    if mode & 0o400 != 0 {
        buf[0] = b'r';
    }
    if mode & 0o200 != 0 {
        buf[1] = b'w';
    }
    if mode & 0o100 != 0 {
        buf[2] = b'x';
    }
    // group
    if mode & 0o040 != 0 {
        buf[3] = b'r';
    }
    if mode & 0o020 != 0 {
        buf[4] = b'w';
    }
    if mode & 0o010 != 0 {
        buf[5] = b'x';
    }
    // other
    if mode & 0o004 != 0 {
        buf[6] = b'r';
    }
    if mode & 0o002 != 0 {
        buf[7] = b'w';
    }
    if mode & 0o001 != 0 {
        buf[8] = b'x';
    }

    // special bits
    if mode & S_ISUID != 0 {
        buf[2] = if buf[2] == b'x' { b's' } else { b'S' };
    }
    if mode & S_ISGID != 0 {
        buf[5] = if buf[5] == b'x' { b's' } else { b'S' };
    }
    if mode & S_ISVTX != 0 {
        buf[8] = if buf[8] == b'x' { b't' } else { b'T' };
    }

    let mut s = String::with_capacity(10);
    s.push(file_ch);
    s.push_str(std::str::from_utf8(&buf).unwrap());
    s
}

impl Inode {
    pub fn from_bytes(i_num: u64, data: &[u8], inode_size: u64) -> Self {
        // Some helper functions to read u16 and u32. We could use Cursor in the futur that could be good.
        let le_u16 = |offset: usize| -> u16 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
        };
        let le_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };

        let format_time = |seconds: u32, extra: u32| {
            if extra > 0 {
                let raw_nsec = (extra & EXT4_NSEC_MASK) >> 2;
                Utc.timestamp_opt(seconds as i64, raw_nsec)
                    .single()
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default()
            } else {
                Utc.timestamp_opt(seconds as i64, 0)
                    .single()
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default()
            }
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

        let mut i_block = [0u32; 15];
        for i in 0..15 {
            i_block[i] = le_u32(0x28 + i * 4);
        }

        // Some fields exist after offset 128 only if inode_size >= 256 (ext4)
        let i_generation = if inode_size >= 256 { le_u32(0x64) } else { 0 };
        let i_file_acl_lo = if inode_size >= 256 { le_u32(0x68) } else { 0 };
        let i_size_high = if inode_size >= 256 { le_u32(0x6C) } else { 0 };
        let l_i_blocks_high = if inode_size >= 256 { le_u16(0x74) } else { 0 };
        let l_i_file_acl_high = if inode_size >= 256 { le_u16(0x76) } else { 0 };
        let l_i_uid_high = if inode_size >= 256 { le_u16(0x78) } else { 0 };
        let l_i_gid_high = if inode_size >= 256 { le_u16(0x7A) } else { 0 };
        let l_i_checksum_lo = if inode_size >= 256 { le_u16(0x7C) } else { 0 };
        let i_extra_isize = if inode_size >= 256 { le_u16(0x80) } else { 0 };
        let i_checksum_hi = if inode_size >= 256 { le_u16(0x82) } else { 0 };
        let i_ctime_extra = if inode_size >= 256 { le_u32(0x84) } else { 0 };
        let i_mtime_extra = if inode_size >= 256 { le_u32(0x88) } else { 0 };
        let i_atime_extra = if inode_size >= 256 { le_u32(0x8C) } else { 0 };
        let i_crtime = if inode_size >= 256 { le_u32(0x90) } else { 0 };
        let i_crtime_extra = if inode_size >= 256 { le_u32(0x94) } else { 0 };
        let i_projid = if inode_size >= 256 { le_u32(0x9C) } else { 0 };

        // Construct the inode.
        Inode {
            i_num,
            i_mode,
            i_uid,
            i_size_lo,
            i_atime,
            i_ctime,
            i_mtime,
            i_dtime,
            i_atime_h: format_time(i_atime, i_atime_extra),
            i_ctime_h: format_time(i_ctime, i_ctime_extra),
            i_mtime_h: format_time(i_mtime, i_mtime_extra),
            i_dtime_h: format_time(i_dtime, 0),
            i_gid,
            i_links_count: i_links_cnt,
            i_blocks_lo,
            i_flags,
            i_block,
            i_generation,
            i_file_acl_lo,
            i_size_high,
            l_i_blocks_high,
            l_i_file_acl_high,
            l_i_uid_high,
            l_i_gid_high,
            l_i_checksum_lo,
            i_extra_isize,
            i_checksum_hi,
            i_ctime_extra,
            i_mtime_extra,
            i_atime_extra,
            i_crtime,
            i_crtime_extra,
            i_crtime_h: format_time(i_crtime, i_crtime_extra),
            i_projid,
        }
    }

    /// Returns the full 64-bit size of the file by combining `i_size_lo` and
    /// `i_size_high`.
    pub fn size(&self) -> u64 {
        ((self.i_size_high as u64) << 32) | (self.i_size_lo as u64)
    }

    /// Returns the i_mode
    pub fn mode(&self) -> u16 {
        self.i_mode
    }

    /// Returns the i_flag
    pub fn flag(&self) -> u32 {
        self.i_flags
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

    /// Combined 32-bit checksum (l_i_checksum_lo + i_checksum_hi)
    /// The "low" part is 16 bits, and the "high" part is another 16 bits.
    pub fn checksum(&self) -> u32 {
        ((self.i_checksum_hi as u32) << 16) | (self.l_i_checksum_lo as u32)
    }

    /// Combined 48-bit file ACL (i_file_acl_lo + l_i_file_acl_high).
    /// The `i_file_acl_lo` is 32 bits, and `l_i_file_acl_high` is 16 bits.
    pub fn file_acl(&self) -> u64 {
        ((self.l_i_file_acl_high as u64) << 32) | (self.i_file_acl_lo as u64)
    }

    /// The to_json method.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }

    /// String representation of an Inode using prettytable
    pub fn to_string(&self) -> String {
        let mut inode_table = Table::new();

        inode_table.add_row(Row::new(vec![
            Cell::new("Identifier"),
            Cell::new(&format!("0x{:x}", self.i_num)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Mode"),
            Cell::new(&format!("0x{:x}", self.i_mode)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Links Count"),
            Cell::new(&format!("{}", self.i_links_count)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Flags"),
            Cell::new(&format!("0x{:x}", self.i_flags)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("atime (Change Time)"),
            Cell::new(&self.i_atime_h),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("ctime (Creation Time)"),
            Cell::new(&self.i_ctime_h),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("mtime (Modification Time)"),
            Cell::new(&self.i_mtime_h),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("dtime (Deletion Time)"),
            Cell::new(&self.i_dtime_h),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Block Pointers"),
            Cell::new(&format!("{:?}", self.block_pointers())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Generation"),
            Cell::new(&format!("0x{:x}", self.i_generation)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("extra_isize"),
            Cell::new(&format!("0x{:x}", self.i_extra_isize)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Project ID"),
            Cell::new(&format!("0x{:x}", self.i_projid)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("UID"),
            Cell::new(&format!("0x{:x}", self.uid())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("GID"),
            Cell::new(&format!("0x{:x}", self.gid())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Size"),
            Cell::new(&format!("0x{:x}", self.size())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Blocks"),
            Cell::new(&format!("{}", self.block_count())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Checksum"),
            Cell::new(&format!("0x{:x}", self.checksum())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("File ACL"),
            Cell::new(&format!("0x{:x}", self.file_acl())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Dir?"),
            Cell::new(&format!("{}", self.is_dir())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Regular?"),
            Cell::new(&format!("{}", self.is_regular_file())),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("Symlink?"),
            Cell::new(&format!("{}", self.is_symlink())),
        ]));
        // Timestamp rows
        inode_table.add_row(Row::new(vec![
            Cell::new("atime (raw)"),
            Cell::new(&format!("0x{:x}", self.i_atime)),
        ]));

        inode_table.add_row(Row::new(vec![
            Cell::new("ctime (raw)"),
            Cell::new(&format!("0x{:x}", self.i_ctime)),
        ]));

        inode_table.add_row(Row::new(vec![
            Cell::new("mtime (raw)"),
            Cell::new(&format!("0x{:x}", self.i_mtime)),
        ]));

        inode_table.add_row(Row::new(vec![
            Cell::new("dtime (raw)"),
            Cell::new(&format!("0x{:x}", self.i_dtime)),
        ]));

        inode_table.add_row(Row::new(vec![
            Cell::new("ctime_extra"),
            Cell::new(&format!("0x{:x}", self.i_ctime_extra)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("mtime_extra"),
            Cell::new(&format!("0x{:x}", self.i_mtime_extra)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("atime_extra"),
            Cell::new(&format!("0x{:x}", self.i_atime_extra)),
        ]));
        inode_table.add_row(Row::new(vec![
            Cell::new("crtime_extra"),
            Cell::new(&format!("0x{:x}", self.i_crtime_extra)),
        ]));
        inode_table.to_string()
    }
}
