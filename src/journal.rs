// REF: https://www.kernel.org/doc/html/latest/filesystems/ext4/journal.html
use log::debug;
use serde::{Deserialize, Serialize};

/// 0xC03B_3998 in big-endian
pub const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Helper to read BE numbers -------------------------------------------------
#[inline(always)]
fn be_u32(data: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(data[off..off + 4].try_into().unwrap())
}
#[inline(always)]
fn be_u64(data: &[u8], off: usize) -> u64 {
    u64::from_be_bytes(data[off..off + 8].try_into().unwrap())
}
#[inline(always)]
fn be_u16(data: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(data[off..off + 2].try_into().unwrap())
}

// This structure is part of the EXTFS Superblock if the feature is present.
#[derive(Debug, Serialize, Deserialize)]
pub struct Journaling {
    pub s_journal_uuid: [u8; 16],
    pub s_journal_inum: u32,
    pub s_journal_dev: u32,
    pub s_last_orphan: u32,
    pub s_hash_seed: [u32; 4],
    pub s_def_hash_version: u8,
    pub s_jnl_backup_type: u8,
    pub s_desc_size: u16,
    pub s_default_mount_opts: u32,
    pub s_first_meta_bg: u32,
    pub s_mkfs_time: u64,
    pub s_jnl_blocks: [u32; 17],
}

impl Journaling {
    pub fn from_bytes(data: &[u8]) -> Self {
        debug!("Parsing Journal metadata from the superblock.");
        let le_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };
        let le_u16 = |offset: usize| -> u16 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
        };
        let lo = le_u32(0x108) as u64;
        Self {
            s_journal_uuid: data[0xD0..0xE0].try_into().unwrap(),
            s_journal_inum: le_u32(0xE0),
            s_journal_dev: le_u32(0xE4),
            s_last_orphan: le_u32(0xE8),
            s_hash_seed: [le_u32(0xEC), le_u32(0xF0), le_u32(0xF4), le_u32(0xF8)],
            s_def_hash_version: data[0xFC],
            s_jnl_backup_type: data[0xFD],
            s_desc_size: le_u16(0xFE),
            s_default_mount_opts: le_u32(0x100),
            s_first_meta_bg: le_u32(0x104),
            s_mkfs_time: lo,
            s_jnl_blocks: [
                le_u32(0x10C),
                le_u32(0x110),
                le_u32(0x114),
                le_u32(0x118),
                le_u32(0x11C),
                le_u32(0x120),
                le_u32(0x124),
                le_u32(0x128),
                le_u32(0x12C),
                le_u32(0x130),
                le_u32(0x134),
                le_u32(0x138),
                le_u32(0x13C),
                le_u32(0x140),
                le_u32(0x144),
                le_u32(0x148),
                le_u32(0x14C),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum JournalBlockType {
    Descriptor = 1,
    Commit = 2,
    SuperblockV1 = 3,
    SuperblockV2 = 4,
    Revoke = 5,
    Unknown = 0xFFFF_FFFF,
}

impl From<u32> for JournalBlockType {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::Descriptor,
            2 => Self::Commit,
            3 => Self::SuperblockV1,
            4 => Self::SuperblockV2,
            5 => Self::Revoke,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalBlockHeader {
    pub h_magic: u32,
    pub h_blocktype: JournalBlockType,
    pub h_sequence: u32,
}

impl JournalBlockHeader {
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            h_magic: be_u32(data, 0),
            h_blocktype: JournalBlockType::from(be_u32(data, 4)),
            h_sequence: be_u32(data, 8),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalSuperblock {
    pub header: JournalBlockHeader,
    /* static fields */
    pub s_blocksize: u32,
    pub s_maxlen: u32,
    pub s_first: u32,
    /* dynamic fields */
    pub s_sequence: u32,
    pub s_start: u32,
    pub s_errno: u32,
    /* v2-only feature flags (zero for v1) */
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_nr_users: u32,
    pub s_dynsuper: u32,
    pub s_max_transaction: u32,
    pub s_max_trans_data: u32,
}

impl JournalSuperblock {
    pub fn from_bytes(data: &[u8]) -> Self {
        debug!("Parsing JBD2 journal super-block.");
        Self {
            header: JournalBlockHeader::from_bytes(data),
            s_blocksize: be_u32(data, 0x0C),
            s_maxlen: be_u32(data, 0x10),
            s_first: be_u32(data, 0x14),
            s_sequence: be_u32(data, 0x18),
            s_start: be_u32(data, 0x1C),
            s_errno: be_u32(data, 0x20),
            s_feature_compat: be_u32(data, 0x24),
            s_feature_incompat: be_u32(data, 0x28),
            s_feature_ro_compat: be_u32(data, 0x2C),
            s_uuid: data[0x30..0x40].try_into().unwrap(),
            s_nr_users: be_u32(data, 0x40),
            s_dynsuper: be_u32(data, 0x44),
            s_max_transaction: be_u32(data, 0x48),
            s_max_trans_data: be_u32(data, 0x4C),
        }
    }

    /// Check 64-bit block numbers.
    pub fn has_64bit(&self) -> bool {
        self.s_feature_incompat & 0x01 != 0 // JBD2_FEATURE_INCOMPAT_64BIT
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalBlockTag {
    pub blocknr: u64,  // always expanded to 64-bit in memory
    pub checksum: u32, // keep full 32 bits – low 16 bits used for v1/v2
    pub flags: u16,
    pub has_uuid: bool,
}

impl JournalBlockTag {
    /// Returns (tag, bytes_read)
    fn parse(data: &[u8], has_64bit: bool, previous_had_same_uuid: bool) -> (Self, usize) {
        let blocknr = be_u32(data, 0) as u64;
        let checksum_or_flags = be_u16(data, 4);
        let flags = be_u16(data, 6);

        let mut consumed = 8;

        let (blocknr, checksum) = if has_64bit {
            // 64-bit block number, 32-bit checksum after flags
            let high = be_u32(data, 8) as u64;
            consumed += 4;
            let checksum = be_u32(data, 12);
            consumed += 4;
            ((high << 32) | blocknr, checksum)
        } else {
            (blocknr, checksum_or_flags as u32)
        };

        // Optional UUID (16 bytes) if SAME_UUID flag *not* set
        let has_uuid = (flags & 0x2) == 0 && !previous_had_same_uuid;
        if has_uuid {
            consumed += 16;
        }

        (
            Self {
                blocknr,
                checksum,
                flags,
                has_uuid,
            },
            consumed,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalDescriptorBlock {
    pub header: JournalBlockHeader,
    pub tags: Vec<JournalBlockTag>,
}

impl JournalDescriptorBlock {
    pub fn from_bytes(data: &[u8], has_64bit: bool) -> Self {
        debug!("Parsing JBD2 descriptor block.");
        let header = JournalBlockHeader::from_bytes(data);
        let mut offset = 12; // first tag after common header
        let mut tags = Vec::new();
        let mut previous_tag_had_same_uuid = false;

        while offset + 8 <= data.len() {
            let (tag, len) =
                JournalBlockTag::parse(&data[offset..], has_64bit, previous_tag_had_same_uuid);
            previous_tag_had_same_uuid = !tag.has_uuid;
            offset += len;
            tags.push(tag.clone());

            // last-tag flag means we can stop early
            if tag.flags & 0x8 != 0 {
                break;
            }
        }

        Self { header, tags }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JournalRevokeBlock {
    pub header: JournalBlockHeader,
    pub r_count: u32,
    pub revoked: Vec<u64>,
}

impl JournalRevokeBlock {
    pub fn from_bytes(data: &[u8], has_64bit: bool) -> Self {
        debug!("Parsing JBD2 revoke block.");
        let header = JournalBlockHeader::from_bytes(data);
        let r_count = be_u32(data, 0x0C) as usize; // bytes used
        let stride = if has_64bit { 8 } else { 4 };

        let mut revoked = Vec::new();
        let mut off = 0x10;
        while off + stride <= 0x10 + r_count {
            let blk = if has_64bit {
                be_u64(data, off)
            } else {
                be_u32(data, off) as u64
            };
            revoked.push(blk);
            off += stride;
        }

        Self {
            header,
            r_count: r_count as u32,
            revoked,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JournalCommitBlock {
    pub header: JournalBlockHeader,
    pub chksum_type: u8,
    pub chksum_size: u8,
    pub checksum: [u32; 8],
    pub commit_sec: u64,
    pub commit_nsec: u32,
}

impl JournalCommitBlock {
    pub fn from_bytes(data: &[u8]) -> Self {
        debug!("Parsing JBD2 commit block.");
        let header = JournalBlockHeader::from_bytes(data);

        let chksum_type = data[0x0C];
        let chksum_size = data[0x0D];

        let mut checksum = [0u32; 8];
        for (i, c) in checksum.iter_mut().enumerate() {
            *c = be_u32(data, 0x10 + i * 4);
        }

        let commit_sec = be_u64(data, 0x30);
        let commit_nsec = be_u32(data, 0x38);

        Self {
            header,
            chksum_type,
            chksum_size,
            checksum,
            commit_sec,
            commit_nsec,
        }
    }
}
