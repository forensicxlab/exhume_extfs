/// Reference: https://www.kernel.org/doc/html/v4.19/filesystems/ext4/ondisk/index.html#super-block
use exhume_body::Body;

const EXT_MAGIC: u16 = 0xEF53;
const INCOMPAT_EXTENTS: u32 = 0x40;
const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x4;
const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x80000; // 64-bit feature flag

#[derive(Debug)]
struct Performance {
    s_prealloc_blocks: u8, // # of blocks to try to preallocate for files (Not used in e2fsprogs/Linux)
    s_prealloc_dir_blocks: u8, // Number of blocks to preallocate for directories (Not used in e2fsprogs/Linux)
}

#[derive(Debug)]
struct Journaling {
    s_journal_uuid: [u8; 16],  // UUID of journal superblock
    s_journal_inum: u32,       // inode number of journal file.
    s_journal_dev: u32, // Device number of journal file, if the external journal feature flag is set.
    s_last_orphan: u32, // Start of list of orphaned inodes to delete.
    s_hash_seed: [u32; 4], // HTREE hash seed.
    s_def_hash_version: u8, // Default hash algorithm to use for directory hashes.
    s_jnl_backup_type: u8, // If this value is 0 or EXT3_JNL_BACKUP_BLOCKS (1), then the s_jnl_blocks field contains a duplicate copy of the inode’s i_block[] array and i_size.
    s_desc_size: u16, // Size of group descriptors, in bytes, if the 64bit incompat feature flag is set.
    s_default_mount_opts: u32, // Default mount options.
    s_first_meta_bg: u32, // First metablock block group, if the meta_bg feature is enabled.
    s_mkfs_time: u32, // When the filesystem was created, in seconds since the epoch.
    s_jnl_blocks: [u32; 17], // Backup copy of the journal inode’s i_block[] array.
}

impl Journaling {
    fn from_bytes(data: &Vec<u8>) -> Journaling {
        Journaling {
            s_journal_uuid: data[0xD0..0xE0].try_into().unwrap(),
            s_journal_inum: u32::from_le_bytes(data[0xE0..0xE4].try_into().unwrap()),
            s_journal_dev: u32::from_le_bytes(data[0xE4..0xE8].try_into().unwrap()),
            s_last_orphan: u32::from_le_bytes(data[0xE8..0xEC].try_into().unwrap()),
            s_hash_seed: [
                u32::from_le_bytes(data[0xEC..0xF0].try_into().unwrap()),
                u32::from_le_bytes(data[0xF0..0xF4].try_into().unwrap()),
                u32::from_le_bytes(data[0xF4..0xF8].try_into().unwrap()),
                u32::from_le_bytes(data[0xF8..0xFC].try_into().unwrap()),
            ],
            s_def_hash_version: data[0xFC],
            s_jnl_backup_type: data[0xFD],
            s_desc_size: u16::from_le_bytes(data[0xFE..0x100].try_into().unwrap()),
            s_default_mount_opts: u32::from_le_bytes(data[0x100..0x104].try_into().unwrap()),
            s_first_meta_bg: u32::from_le_bytes(data[0x104..0x108].try_into().unwrap()),
            s_mkfs_time: u32::from_le_bytes(data[0x108..0x10C].try_into().unwrap()),
            s_jnl_blocks: [
                u32::from_le_bytes(data[0x10C..0x110].try_into().unwrap()),
                u32::from_le_bytes(data[0x110..0x114].try_into().unwrap()),
                u32::from_le_bytes(data[0x114..0x118].try_into().unwrap()),
                u32::from_le_bytes(data[0x118..0x11C].try_into().unwrap()),
                u32::from_le_bytes(data[0x11C..0x120].try_into().unwrap()),
                u32::from_le_bytes(data[0x120..0x124].try_into().unwrap()),
                u32::from_le_bytes(data[0x124..0x128].try_into().unwrap()),
                u32::from_le_bytes(data[0x128..0x12C].try_into().unwrap()),
                u32::from_le_bytes(data[0x12C..0x130].try_into().unwrap()),
                u32::from_le_bytes(data[0x130..0x134].try_into().unwrap()),
                u32::from_le_bytes(data[0x134..0x138].try_into().unwrap()),
                u32::from_le_bytes(data[0x138..0x13C].try_into().unwrap()),
                u32::from_le_bytes(data[0x13C..0x140].try_into().unwrap()),
                u32::from_le_bytes(data[0x140..0x144].try_into().unwrap()),
                u32::from_le_bytes(data[0x144..0x148].try_into().unwrap()),
                u32::from_le_bytes(data[0x148..0x14C].try_into().unwrap()),
                u32::from_le_bytes(data[0x14C..0x150].try_into().unwrap()),
            ],
        }
    }
}

#[derive(Debug)]
struct Superblock64 {
    s_blocks_count_hi: u32,         // High 32-bits of the block count.
    s_r_blocks_count_hi: u32,       // High 32-bits of the reserved block count.
    s_free_blocks_count_hi: u32,    // High 32-bits of the free block count.
    s_min_extra_isize: u16,         // All inodes have at least # bytes.
    s_want_extra_isize: u16,        // New inodes should reserve # bytes.
    s_flags: u32,                   // Miscellaneous flags.
    s_raid_stride: u16,             // RAID stride.
    s_mmp_interval: u16,            // # seconds to wait in multi-mount prevention (MMP) checking.
    s_mmp_block: u64,               // Block # for multi-mount protection data.
    s_raid_stripe_width: u32,       // RAID stripe width.
    s_log_groups_per_flex: u8,      // Size of a flexible block group is 2 ^ s_log_groups_per_flex.
    s_checksum_type: u8,            // Metadata checksum algorithm type.
    s_kbytes_written: u64,          // Number of KiB written to this filesystem over its lifetime.
    s_snapshot_inum: u32,           // inode number of active snapshot.
    s_snapshot_id: u32,             // Sequential ID of active snapshot.
    s_snapshot_r_blocks_count: u64, // Number of blocks reserved for active snapshot’s future use.
    s_snapshot_list: u32,           // inode number of the head of the on-disk snapshot list.
    s_error_count: u32,             // Number of errors seen.
    s_first_error_time: u32,        // First time an error happened, in seconds since the epoch.
    s_first_error_ino: u32,         // inode involved in first error.
    s_first_error_block: u64,       // Number of block involved of first error.
    s_first_error_func: [u8; 32],   // Name of function where the error happened.
    s_first_error_line: u32,        // Line number where error happened.
    s_last_error_time: u32,         // Time of most recent error, in seconds since the epoch.
    s_last_error_ino: u32,          // Inode involved in most recent error.
    s_last_error_line: u32,         // Line number where most recent error happened.
    s_last_error_block: u64,        // Number of block involved in most recent error.
    s_last_error_func: [u8; 32],    // Name of function where the most recent error happened.
    s_mount_opts: [u8; 64],         // ASCIIZ string of mount options.
    s_usr_quota_inum: u32,          // Inode number of user quota file.
    s_grp_quota_inum: u32,          // Inode number of group quota file.
    s_overhead_blocks: u32,         // Overhead blocks/clusters in fs.
    s_backup_bgs: [u32; 2],         // Block groups containing superblock backups.
    s_encrypt_algos: [u8; 4],       // Encryption algorithms in use.
    s_encrypt_pw_salt: [u8; 16],    // Salt for the string2key algorithm for encryption.
    s_lpf_ino: u32,                 // Inode number of lost+found.
    s_prj_quota_inum: u32,          // Inode that tracks project quotas.
    s_checksum_seed: u32,           // Checksum seed used for metadata_csum calculations.
    s_wtime_hi: u8,                 // Upper 8 bits of the s_wtime field.
    s_mtime_hi: u8,                 // Upper 8 bits of the s_mtime field.
    s_mkfs_time_hi: u8,             // Upper 8 bits of the s_mkfs_time field.
    s_lastcheck_hi: u8,             // Upper 8 bits of the s_lastcheck field.
    s_first_error_time_hi: u8,      // Upper 8 bits of s_first_error_time.
    s_last_error_time_hi: u8,       // Upper 8 bits of s_last_error_time.
    s_checksum: u32,                // Superblock checksum.
}

impl Superblock64 {
    fn from_bytes(data: &Vec<u8>) -> Superblock64 {
        Superblock64 {
            s_blocks_count_hi: u32::from_le_bytes(data[0x150..0x154].try_into().unwrap()),
            s_r_blocks_count_hi: u32::from_le_bytes(data[0x154..0x158].try_into().unwrap()),
            s_free_blocks_count_hi: u32::from_le_bytes(data[0x158..0x15C].try_into().unwrap()),
            s_min_extra_isize: u16::from_le_bytes(data[0x15C..0x15E].try_into().unwrap()),
            s_want_extra_isize: u16::from_le_bytes(data[0x15E..0x160].try_into().unwrap()),
            s_flags: u32::from_le_bytes(data[0x160..0x164].try_into().unwrap()),
            s_raid_stride: u16::from_le_bytes(data[0x164..0x166].try_into().unwrap()),
            s_mmp_interval: u16::from_le_bytes(data[0x166..0x168].try_into().unwrap()),
            s_mmp_block: u64::from_le_bytes(data[0x168..0x170].try_into().unwrap()),
            s_raid_stripe_width: u32::from_le_bytes(data[0x170..0x174].try_into().unwrap()),
            s_log_groups_per_flex: data[0x174],
            s_checksum_type: data[0x175],
            s_kbytes_written: u64::from_le_bytes(data[0x178..0x180].try_into().unwrap()),
            s_snapshot_inum: u32::from_le_bytes(data[0x180..0x184].try_into().unwrap()),
            s_snapshot_id: u32::from_le_bytes(data[0x184..0x188].try_into().unwrap()),
            s_snapshot_r_blocks_count: u64::from_le_bytes(data[0x188..0x190].try_into().unwrap()),
            s_snapshot_list: u32::from_le_bytes(data[0x190..0x194].try_into().unwrap()),
            s_error_count: u32::from_le_bytes(data[0x194..0x198].try_into().unwrap()),
            s_first_error_time: u32::from_le_bytes(data[0x198..0x19C].try_into().unwrap()),
            s_first_error_ino: u32::from_le_bytes(data[0x19C..0x1A0].try_into().unwrap()),
            s_first_error_block: u64::from_le_bytes(data[0x1A0..0x1A8].try_into().unwrap()),
            s_first_error_func: data[0x1A8..0x1C8].try_into().unwrap(),
            s_first_error_line: u32::from_le_bytes(data[0x1C8..0x1CC].try_into().unwrap()),
            s_last_error_time: u32::from_le_bytes(data[0x1CC..0x1D0].try_into().unwrap()),
            s_last_error_ino: u32::from_le_bytes(data[0x1D0..0x1D4].try_into().unwrap()),
            s_last_error_line: u32::from_le_bytes(data[0x1D4..0x1D8].try_into().unwrap()),
            s_last_error_block: u64::from_le_bytes(data[0x1D8..0x1E0].try_into().unwrap()),
            s_last_error_func: data[0x1E0..0x200].try_into().unwrap(),
            s_mount_opts: data[0x200..0x240].try_into().unwrap(),
            s_usr_quota_inum: u32::from_le_bytes(data[0x240..0x244].try_into().unwrap()),
            s_grp_quota_inum: u32::from_le_bytes(data[0x244..0x248].try_into().unwrap()),
            s_overhead_blocks: u32::from_le_bytes(data[0x248..0x24C].try_into().unwrap()),
            s_backup_bgs: [
                u32::from_le_bytes(data[0x24C..0x250].try_into().unwrap()),
                u32::from_le_bytes(data[0x250..0x254].try_into().unwrap()),
            ],
            s_encrypt_algos: data[0x254..0x258].try_into().unwrap(),
            s_encrypt_pw_salt: data[0x258..0x268].try_into().unwrap(),
            s_lpf_ino: u32::from_le_bytes(data[0x268..0x26C].try_into().unwrap()),
            s_prj_quota_inum: u32::from_le_bytes(data[0x26C..0x270].try_into().unwrap()),
            s_checksum_seed: u32::from_le_bytes(data[0x270..0x274].try_into().unwrap()),
            s_wtime_hi: data[0x274],
            s_mtime_hi: data[0x275],
            s_mkfs_time_hi: data[0x276],
            s_lastcheck_hi: data[0x277],
            s_first_error_time_hi: data[0x278],
            s_last_error_time_hi: data[0x279],
            s_checksum: u32::from_le_bytes(data[0x27C..0x280].try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
pub struct Superblock {
    s_inodes_count: u32,            // Total inode count.
    s_blocks_count_lo: u32,         // Total block count.
    s_r_blocks_count_lo: u32,       // Reserved blocks count.
    s_free_blocks_count_lo: u32,    // Free block count.
    s_free_inodes_count: u32,       // Free inode count.
    s_first_data_block: u32,        // First data block.
    s_log_block_size: u32,          // Block size is 2 ^ (10 + s_log_block_size).
    s_log_cluster_size: u32, // Cluster size is (2 ^ s_log_cluster_size) blocks if bigalloc is enabled.
    s_blocks_per_group: u32, // Blocks per group.
    s_clusters_per_group: u32, // Clusters per group.
    s_inodes_per_group: u32, // Inodes per group.
    s_mtime: u32,            // Mount time, in seconds since the epoch.
    s_wtime: u32,            // Write time, in seconds since the epoch.
    s_mnt_count: u16,        // Number of mounts since the last fsck.
    s_max_mnt_count: u16,    // Number of mounts beyond which a fsck is needed.
    s_magic: u16,            // Magic signature, 0xEF53
    s_state: u16,            // File system state.
    s_errors: u16,           // Behaviour when detecting errors.
    s_minor_rev_level: u16,  // Minor revision level.
    s_lastcheck: u32,        // Time of last check, in seconds since the epoch.
    s_checkinterval: u32,    // Maximum time between checks, in seconds.
    s_creator_os: u32,       // Creator OS.
    s_rev_level: u32,        // Revision level.
    s_def_resuid: u16,       // Default uid for reserved blocks.
    s_def_resgid: u16,       // Default gid for reserved blocks.
    s_first_ino: u32,        // First non-reserved inode.
    s_inode_size: u16,       // Size of inode structure, in bytes.
    s_block_group_nr: u16,   // Block group # of this superblock.
    s_feature_compat: u32,   // Compatible feature set.
    s_feature_incompat: u32, // Incompatible feature set.
    s_feature_ro_compat: u32, // Readonly-compatible feature set.
    s_uuid: [u8; 16],        // 128-bit UUID for volume.
    s_volume_name: [u8; 16], // Volume label.
    s_last_mounted: [u8; 64], // Directory where filesystem was last mounted.
    s_algorithm_usage_bitmap: u32, // For compression (Not used in e2fsprogs/Linux)
    s_performances: Performance, // Performance hints.
    s_journal: Option<Journaling>, // Journalling support.
    s_64_bit: Option<Superblock64>, // 64bit support.
}

impl Superblock {
    pub fn new(body: &mut Body, partition_offset: &usize) -> Result<Superblock, String> {
        // Seek to the superblock offset.
        body.seek(*partition_offset + 0x400);

        // Read the superblock data
        let data: Vec<u8> = body.read(0x400); // Read 1024 bytes

        let s_inodes_count = u32::from_le_bytes(data[0x00..0x04].try_into().unwrap());
        let s_blocks_count_lo = u32::from_le_bytes(data[0x04..0x08].try_into().unwrap());
        let s_r_blocks_count_lo = u32::from_le_bytes(data[0x08..0x0C].try_into().unwrap());
        let s_free_blocks_count_lo = u32::from_le_bytes(data[0x0C..0x10].try_into().unwrap());
        let s_free_inodes_count = u32::from_le_bytes(data[0x10..0x14].try_into().unwrap());
        let s_first_data_block = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap());
        let s_log_block_size = u32::from_le_bytes(data[0x18..0x1C].try_into().unwrap());
        let s_log_cluster_size = u32::from_le_bytes(data[0x1C..0x20].try_into().unwrap());
        let s_blocks_per_group = u32::from_le_bytes(data[0x20..0x24].try_into().unwrap());
        let s_clusters_per_group = u32::from_le_bytes(data[0x24..0x28].try_into().unwrap());
        let s_inodes_per_group = u32::from_le_bytes(data[0x28..0x2C].try_into().unwrap());
        let s_mtime = u32::from_le_bytes(data[0x2C..0x30].try_into().unwrap());
        let s_wtime = u32::from_le_bytes(data[0x30..0x34].try_into().unwrap());
        let s_mnt_count = u16::from_le_bytes(data[0x34..0x36].try_into().unwrap());
        let s_max_mnt_count = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap());
        let s_magic = u16::from_le_bytes(data[0x38..0x3A].try_into().unwrap());
        let s_state = u16::from_le_bytes(data[0x3A..0x3C].try_into().unwrap());
        let s_errors = u16::from_le_bytes(data[0x3C..0x3E].try_into().unwrap());
        let s_minor_rev_level = u16::from_le_bytes(data[0x3E..0x40].try_into().unwrap());
        let s_lastcheck = u32::from_le_bytes(data[0x40..0x44].try_into().unwrap());
        let s_checkinterval = u32::from_le_bytes(data[0x44..0x48].try_into().unwrap());
        let s_creator_os = u32::from_le_bytes(data[0x48..0x4C].try_into().unwrap());
        let s_rev_level = u32::from_le_bytes(data[0x4C..0x50].try_into().unwrap());
        let s_def_resuid = u16::from_le_bytes(data[0x50..0x52].try_into().unwrap());
        let s_def_resgid = u16::from_le_bytes(data[0x52..0x54].try_into().unwrap());
        let s_first_ino = u32::from_le_bytes(data[0x54..0x58].try_into().unwrap());
        let s_inode_size = u16::from_le_bytes(data[0x58..0x5A].try_into().unwrap());
        let s_block_group_nr = u16::from_le_bytes(data[0x5A..0x5C].try_into().unwrap());
        let s_feature_compat = u32::from_le_bytes(data[0x5C..0x60].try_into().unwrap());
        let s_feature_incompat = u32::from_le_bytes(data[0x60..0x64].try_into().unwrap());
        let s_feature_ro_compat = u32::from_le_bytes(data[0x64..0x68].try_into().unwrap());
        let s_uuid = data[0x68..0x78].try_into().unwrap();
        let s_volume_name = data[0x78..0x88].try_into().unwrap();
        let s_last_mounted = data[0x88..0xC8].try_into().unwrap();
        let s_algorithm_usage_bitmap = u32::from_le_bytes(data[0xC8..0xCC].try_into().unwrap());

        if s_magic != EXT_MAGIC {
            return Err("Invalid FileSystem".to_string());
        }

        if s_blocks_per_group == 0 || s_inodes_per_group == 0 {
            return Err("Invalid FileSystem".to_string());
        }

        // Parse performance fields
        let s_performances = Performance {
            s_prealloc_blocks: data[0xCC],
            s_prealloc_dir_blocks: data[0xCD],
        };

        // Parse journaling fields if enabled
        let s_journal = if (s_feature_compat & EXT4_FEATURE_COMPAT_HAS_JOURNAL) != 0 {
            Some(Journaling::from_bytes(&data))
        } else {
            None
        };

        // Parse 64-bit fields if enabled
        let s_64_bit = if (s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT) != 0 {
            Some(Superblock64::from_bytes(&data))
        } else {
            None
        };

        Ok(Superblock {
            s_inodes_count,
            s_blocks_count_lo,
            s_r_blocks_count_lo,
            s_free_blocks_count_lo,
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
            s_performances,
            s_journal,
            s_64_bit,
        })
    }

    pub fn is_64bit(&self) -> bool {
        self.s_64_bit.is_some()
    }

    pub fn block_size(&self) -> usize {
        1024 << self.s_log_block_size
    }

    pub fn blocks_per_group(&self) -> u64 {
        self.s_blocks_per_group as u64
    }

    pub fn blocks_count(&self) -> u64 {
        if let Some(ref ext64) = self.s_64_bit {
            ((ext64.s_blocks_count_hi as u64) << 32) | (self.s_blocks_count_lo as u64)
        } else {
            self.s_blocks_count_lo as u64
        }
    }

    pub fn descriptor_size(&self) -> usize {
        if let Some(ref journal) = self.s_journal {
            if self.is_64bit() && journal.s_desc_size != 0 {
                journal.s_desc_size as usize
            } else {
                32
            }
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
}
