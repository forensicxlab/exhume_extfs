/// Reference: https://www.kernel.org/doc/html/v4.19/filesystems/ext4/ondisk/index.html#super-block
use crate::journal::Journaling;
use chrono::{TimeZone, Utc};
use log::{info, warn};
use prettytable::{Cell, Row, Table};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::convert::TryInto;

const EXT_MAGIC: u16 = 0xEF53;
pub const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x4;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x80000;

#[derive(Debug, Serialize, Deserialize)]
pub struct Performance {
    pub s_prealloc_blocks: u8,
    pub s_prealloc_dir_blocks: u8,
}

#[derive(Debug, Serialize, Deserialize)]
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
    pub s_last_mounted: Vec<u8>,
    pub s_algorithm_usage_bitmap: u32,
    pub s_performance: Performance,
    pub s_journaling: Option<Journaling>, //See journal.rs
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
        let s_last_mounted: Vec<u8> = data[0x88..0xC8].to_vec();
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

        let s_journaling = if (s_feature_compat & EXT4_FEATURE_COMPAT_HAS_JOURNAL) != 0 {
            info!("Extended FileSystem Journaling feature is on.");
            Some(Journaling::from_bytes(&data))
        } else {
            warn!("Journaling feature is not available.");
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
            s_journaling,
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

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }

    fn format_uuid(array: &[u8; 16]) -> String {
        array
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("-")
    }

    pub fn to_string(&self) -> String {
        let mut table = Table::new();

        // Adding rows to the table
        table.add_row(Row::new(vec![
            Cell::new("Inodes Count"),
            Cell::new(&self.s_inodes_count.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Blocks Count"),
            Cell::new(&self.s_blocks_count.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Reserved Blocks Count"),
            Cell::new(&self.s_r_blocks_count.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Free Blocks Count"),
            Cell::new(&self.s_free_blocks_count.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Free Inodes Count"),
            Cell::new(&self.s_free_inodes_count.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("First Data Block"),
            Cell::new(&format!("{:#X}", self.s_first_data_block)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Log Block Size"),
            Cell::new(&format!("{:#X}", self.s_log_block_size)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Log Cluster Size"),
            Cell::new(&format!("{:#X}", self.s_log_cluster_size)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Blocks per Group"),
            Cell::new(&self.s_blocks_per_group.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Clusters per Group"),
            Cell::new(&self.s_clusters_per_group.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Inodes per Group"),
            Cell::new(&self.s_inodes_per_group.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Mount Time"),
            Cell::new(&format!(
                "{:?}",
                Utc.timestamp_opt(self.s_mtime as i64, 0)
                    .single()
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default()
            )),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Write Time"),
            Cell::new(&format!(
                "{:?}",
                Utc.timestamp_opt(self.s_wtime as i64, 0)
                    .single()
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default()
            )),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Mount Count"),
            Cell::new(&self.s_mnt_count.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Max Mount Count"),
            Cell::new(&self.s_max_mnt_count.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Magic"),
            Cell::new(&format!("{:#06X}", self.s_magic)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("State"),
            Cell::new(&format!("{:#06X}", self.s_state)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Errors"),
            Cell::new(&format!("{:#06X}", self.s_errors)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Minor Revision Level"),
            Cell::new(&self.s_minor_rev_level.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Last Check"),
            Cell::new(&self.s_lastcheck.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Check Interval"),
            Cell::new(&self.s_checkinterval.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Creator OS"),
            Cell::new(&format!("{:#010X}", self.s_creator_os)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Revision Level"),
            Cell::new(&format!("{:#010X}", self.s_rev_level)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Default Res UID"),
            Cell::new(&self.s_def_resuid.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Default Res GID"),
            Cell::new(&self.s_def_resgid.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("First Inode"),
            Cell::new(&format!("{:#X}", self.s_first_ino)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Inode Size"),
            Cell::new(&self.s_inode_size.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Block Group Number"),
            Cell::new(&self.s_block_group_nr.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Feature Compatible"),
            Cell::new(&format!("{:#010X}", self.s_feature_compat)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Feature Incompatible"),
            Cell::new(&format!("{:#010X}", self.s_feature_incompat)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Feature Read-Only Compatible"),
            Cell::new(&format!("{:#010X}", self.s_feature_ro_compat)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("UUID"),
            Cell::new(&Self::format_uuid(&self.s_uuid)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Volume Name"),
            Cell::new(&String::from_utf8_lossy(&self.s_volume_name).to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Last Mounted"),
            Cell::new(&String::from_utf8_lossy(&self.s_last_mounted).to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Algorithm Usage Bitmap"),
            Cell::new(&format!("{:#010X}", self.s_algorithm_usage_bitmap)),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Performance - Prealloc Blocks"),
            Cell::new(&self.s_performance.s_prealloc_blocks.to_string()),
        ]));
        table.add_row(Row::new(vec![
            Cell::new("Performance - Prealloc Dir Blocks"),
            Cell::new(&self.s_performance.s_prealloc_dir_blocks.to_string()),
        ]));

        // Optionnal display: If the journal is present, we display the Journal section !
        if let Some(journaling) = &self.s_journaling {
            table.add_row(Row::new(vec![
                Cell::new("Journaling - Journal UUID"),
                Cell::new(&Self::format_uuid(&journaling.s_journal_uuid)),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - Journal Inode Number"),
                Cell::new(&journaling.s_journal_inum.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - Device number"),
                Cell::new(&journaling.s_journal_dev.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - Orphaned Inodes List offset"),
                Cell::new(&journaling.s_last_orphan.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - HTREE hash seed"),
                Cell::new(&format!("{:?}", journaling.s_hash_seed)),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - Default hash algorithm"),
                Cell::new(&journaling.s_def_hash_version.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - Backup Type"),
                Cell::new(&journaling.s_jnl_backup_type.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - Descriptor Size"),
                Cell::new(&journaling.s_desc_size.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - Mount options"),
                Cell::new(&journaling.s_default_mount_opts.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - First metablock block group"),
                Cell::new(&journaling.s_first_meta_bg.to_string()),
            ]));

            table.add_row(Row::new(vec![
                Cell::new("Journaling - FileSystem Creation Date"),
                Cell::new(&format!(
                    "{:?}",
                    Utc.timestamp_opt(journaling.s_mkfs_time as i64, 0)
                        .single()
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default()
                )),
            ]));
        }
        table.to_string()
    }
}
