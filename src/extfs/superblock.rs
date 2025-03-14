/// Reference: https://www.kernel.org/doc/html/v4.19/filesystems/ext4/ondisk/index.html#super-block
use serde_json::{json, Value};
use std::convert::TryInto;

const EXT_MAGIC: u16 = 0xEF53;
const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x4;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x80000;

#[derive(Debug)]
pub struct Performance {
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Superblock {
    pub s_inodes_count: u64,
    pub s_blocks_count: u64,
    pub s_r_blocks_count: u64,
    pub s_free_blocks_count: u64,
    pub s_free_inodes_count: u64,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_cluster_size: u32,
    pub s_blocks_per_group: u32,
    pub s_clusters_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u64,
    pub s_wtime: u64,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u64,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_volume_name: [u8; 16],
    pub s_last_mounted: [u8; 64],
    pub s_algorithm_usage_bitmap: u32,
    pub s_performance: Performance,
    pub s_journal: Option<Journaling>,
}

impl Superblock {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 0x400 {
            return Err("Not enough bytes to parse superblock".to_string());
        }
        let le_u16 = |offset: usize| -> u16 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
        };
        let le_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        };
        let le_u8 = |offset: usize| -> u8 { data[offset] };
        let s_inodes_count_lo = le_u32(0x00);
        let s_blocks_count_lo = le_u32(0x04);
        let s_r_blocks_count_lo = le_u32(0x08);
        let s_free_blocks_count_lo = le_u32(0x0C);
        let s_free_inodes_count_lo = le_u32(0x10);
        let s_first_data_block = le_u32(0x14);
        let s_log_block_size = le_u32(0x18);
        let s_log_cluster_size = le_u32(0x1C);
        let s_blocks_per_group = le_u32(0x20);
        let s_clusters_per_group = le_u32(0x24);
        let s_inodes_per_group = le_u32(0x28);
        let s_mtime_lo = le_u32(0x2C);
        let s_wtime_lo = le_u32(0x30);
        let s_mnt_count = le_u16(0x34);
        let s_max_mnt_count = le_u16(0x36);
        let s_magic = le_u16(0x38);
        if s_magic != EXT_MAGIC {
            return Err("Invalid FileSystem".to_string());
        }
        let s_state = le_u16(0x3A);
        let s_errors = le_u16(0x3C);
        let s_minor_rev_level = le_u16(0x3E);
        let s_lastcheck_lo = le_u32(0x40);
        let s_checkinterval = le_u32(0x44);
        let s_creator_os = le_u32(0x48);
        let s_rev_level = le_u32(0x4C);
        let s_def_resuid = le_u16(0x50);
        let s_def_resgid = le_u16(0x52);
        let s_first_ino = le_u32(0x54);
        let s_inode_size = le_u16(0x58);
        let s_block_group_nr = le_u16(0x5A);
        let s_feature_compat = le_u32(0x5C);
        let s_feature_incompat = le_u32(0x60);
        let s_feature_ro_compat = le_u32(0x64);
        let s_uuid: [u8; 16] = data[0x68..0x78].try_into().unwrap();
        let s_volume_name: [u8; 16] = data[0x78..0x88].try_into().unwrap();
        let s_last_mounted: [u8; 64] = data[0x88..0xC8].try_into().unwrap();
        let s_algorithm_usage_bitmap = le_u32(0xC8);
        let s_performance = Performance {
            s_prealloc_blocks: le_u8(0xCC),
            s_prealloc_dir_blocks: le_u8(0xCD),
        };
        let has_64bit = (s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0;
        let s_blocks_count_hi = if has_64bit { le_u32(0x150) } else { 0 };
        let s_r_blocks_count_hi = if has_64bit { le_u32(0x154) } else { 0 };
        let s_free_blocks_count_hi = if has_64bit { le_u32(0x158) } else { 0 };
        let s_wtime_hi = if has_64bit { le_u8(0x274) } else { 0 };
        let s_mtime_hi = if has_64bit { le_u8(0x275) } else { 0 };
        let s_lastcheck_hi = if has_64bit { le_u8(0x277) } else { 0 };
        let s_blocks_count = ((s_blocks_count_hi as u64) << 32) | (s_blocks_count_lo as u64);
        let s_r_blocks_count = ((s_r_blocks_count_hi as u64) << 32) | (s_r_blocks_count_lo as u64);
        let s_free_blocks_count =
            ((s_free_blocks_count_hi as u64) << 32) | (s_free_blocks_count_lo as u64);
        let s_inodes_count = s_inodes_count_lo as u64;
        let s_free_inodes_count = s_free_inodes_count_lo as u64;
        let s_mtime = ((s_mtime_hi as u64) << 32) | (s_mtime_lo as u64);
        let s_wtime = ((s_wtime_hi as u64) << 32) | (s_wtime_lo as u64);
        let s_lastcheck = ((s_lastcheck_hi as u64) << 32) | (s_lastcheck_lo as u64);
        let s_journal = if (s_feature_compat & EXT4_FEATURE_COMPAT_HAS_JOURNAL) != 0 {
            Some(Journaling::from_bytes(data))
        } else {
            None
        };
        Ok(Self {
            s_inodes_count,
            s_blocks_count,
            s_r_blocks_count,
            s_free_blocks_count,
            s_free_inodes_count,
            s_first_data_block,
            s_log_block_size,
            s_log_cluster_size,
            s_blocks_per_group,
            s_clusters_per_group,
            s_inodes_per_group,
            s_mtime,
            s_wtime,
            s_mnt_count,
            s_max_mnt_count,
            s_magic,
            s_state,
            s_errors,
            s_minor_rev_level,
            s_lastcheck,
            s_checkinterval,
            s_creator_os,
            s_rev_level,
            s_def_resuid,
            s_def_resgid,
            s_first_ino,
            s_inode_size,
            s_block_group_nr,
            s_feature_compat,
            s_feature_incompat,
            s_feature_ro_compat,
            s_uuid,
            s_volume_name,
            s_last_mounted,
            s_algorithm_usage_bitmap,
            s_performance,
            s_journal,
        })
    }

    pub fn is_64bit(&self) -> bool {
        (self.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0
    }

    pub fn block_size(&self) -> u64 {
        1024 << self.s_log_block_size
    }

    pub fn blocks_per_group(&self) -> u64 {
        self.s_blocks_per_group as u64
    }

    pub fn blocks_count(&self) -> u64 {
        self.s_blocks_count
    }

    pub fn descriptor_size(&self) -> usize {
        let desc_size = self.s_journal.as_ref().map(|j| j.s_desc_size).unwrap_or(0);
        if (self.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) == 0 && desc_size >= 64 {
            desc_size as usize
        } else {
            32
        }
    }

    pub fn first_data_block(&self) -> usize {
        self.s_first_data_block as usize
    }

    pub fn inodes_per_group(&self) -> usize {
        self.s_inodes_per_group as usize
    }

    pub fn inode_size(&self) -> usize {
        self.s_inode_size as usize
    }

    pub fn feature_incompat(&self) -> u32 {
        self.s_feature_incompat
    }

    pub fn print_sp_info(&self) {
        println!("{:#?}", self);
    }

    pub fn to_json(&self) -> Value {
        json!({
            "inodes_count": self.s_inodes_count,
            "blocks_count": self.s_blocks_count,
            "free_blocks_count": self.s_free_blocks_count,
            "free_inodes_count": self.s_free_inodes_count,
            "log_block_size": self.s_log_block_size,
            "blocks_per_group": self.s_blocks_per_group,
            "inodes_per_group": self.s_inodes_per_group,
            "inode_size": self.s_inode_size,
            "magic": format!("0x{:04x}", self.s_magic),
            "feature_incompat": format!("0x{:08x}", self.s_feature_incompat),
            "feature_compat": format!("0x{:08x}", self.s_feature_compat),
            "feature_ro_compat": format!("0x{:08x}", self.s_feature_ro_compat),
            "is_64bit": self.is_64bit(),
        })
    }
}
