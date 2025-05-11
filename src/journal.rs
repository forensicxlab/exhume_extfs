use log::debug;
use serde::{Deserialize, Serialize};

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
