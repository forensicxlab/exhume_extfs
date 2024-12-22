use crate::image::Image;
use chrono::prelude::*;
use exhume_partitions::part::VPartition;
use std::str;

const EXT_MAGIC: u16 = 0xEF53;
const INCOMPAT_EXTENTS: u32 = 0x40;
const COMPAT_HAS_JOURNAL: u32 = 0x4;
const INCOMPAT_FILETYPE: u32 = 0x2;

enum _FileType {
    Unknown,
    Regular,
    Directory,
    Character,
    Block,
    FIFO,
    Socket,
    Symbolic,
}

enum Type {
    Ext4,
    Ext3,
    Ext2,
}
pub struct ExtFS<'a> {
    partition: &'a mut VPartition,
    superblock: Superblock,
    fstype: Type,
    evidence: &'a mut Image,
}
struct ExtentLeaf {
    ee_block: u32,
    ee_len: u16,
    ee_start: usize,
}
pub struct Inode {
    i_mode: u16,
    i_uid: u16,
    i_size: u64,
    i_atime: u32,
    i_ctime: u32,
    i_mtime: u32,
    i_dtime: u32,
    i_gid: u16,
    i_links_count: u16,
    i_block: Vec<u8>,
    i_flags: u32,
    i_generation: u32,
    i_ctime_extra: u32,
    i_mtime_extra: u32,
    i_atime_extra: u32,
    i_crtime: u32,
    i_crtime_extra: u32,
    i_version_hi: u32,
}
struct ExtentHeader {
    eh_magic: u16,
    eh_entries: u16,
    eh_max: u16,
    eh_depth: u16,
}
pub struct Superblock {
    s_inodes_count: u32,      // Total inode count.
    s_blocks_count: u64,      // Total block count
    s_free_inodes_count: u32, // Free inode count.
    s_first_data_block: u32, // First data block. This must be at least 1 for 1k-block filesystems and is typically 0 for all other block sizes.
    s_log_block_size: u32,   // Block size is 2 ^ (10 + s_log_block_size).
    s_blocks_per_group: u32, // Blocks per group.
    s_inodes_per_group: u32, // Inode per group.
    s_mtime: u32,            // Mount time, in seconds since the epoch.
    s_wtime: u32,            // Write time, in seconds since the epoch.
    s_mnt_count: u16,        // Number of mounts since the last fsck.
    s_first_ino: u32,        // First non-reserved inode.
    s_inode_size: u16,       // Size of inode structure, in bytes.
    s_block_group_nr: u16,   // Block group # of this superblock.
    s_feature_compat: u32,   // Compatible feature
    s_feature_incompat: u32, // Incompatible feature set.
    s_volume_name: String,   // Volume label.
    s_last_mounted: String,  // Directory where filesystem was last mounted.
    s_magic: u16,            // Magic number
    s_desc_size: u16, // Size of group descriptors, in bytes, if the 64bit incompat feature flag is set
}

struct DirEntry {
    inode: u32,
    rec_len: u16,
    file_type: u8,
    name: String,
}

impl DirEntry {
    fn _get_file_type(&self) -> _FileType {
        match self.file_type {
            0x1 => return _FileType::Regular,
            0x2 => return _FileType::Directory,
            0x3 => return _FileType::Character,
            0x4 => return _FileType::Block,
            0x5 => return _FileType::FIFO,
            0x6 => return _FileType::Socket,
            0x7 => return _FileType::Symbolic,
            _ => return _FileType::Unknown,
        }
    }

    fn new(data: &Vec<u8>, comp: u32) -> DirEntry {
        let name_len: usize;
        let ftype: u8;
        if comp & INCOMPAT_FILETYPE != 0 {
            //“filetype” feature flag is set -> ext4_dir_entry_2
            name_len = u8::from_le_bytes(data[0x6..0x7].try_into().unwrap()) as usize;
            ftype = u8::from_le_bytes(data[0x7..0x8].try_into().unwrap());
        } else {
            // -> ext4_dir_entry
            name_len = u16::from_le_bytes(data[0x6..0x8].try_into().unwrap()) as usize;
            ftype = 0x0 //Unknown.
        }

        return DirEntry {
            inode: u32::from_le_bytes(data[0x0..0x4].try_into().unwrap()),
            rec_len: u16::from_le_bytes(data[0x4..0x6].try_into().unwrap()),
            file_type: ftype,
            name: str::from_utf8(&data[0x8..0x8 + name_len])
                .unwrap()
                .to_owned(),
        };
    }

    fn print_info(&self) {
        if self.name.len() > 0 {
            println!("{} :  {} : 0x{:x}", self.inode, self.name, self.file_type);
        }
    }
}

impl ExtentLeaf {
    fn new(data: &Vec<u8>) -> ExtentLeaf {
        let ee_start_hi = u16::from_le_bytes(data[0x6..0x8].try_into().unwrap()) as u32;
        let ee_start_lo = u32::from_le_bytes(data[0x8..0xC].try_into().unwrap());
        return ExtentLeaf {
            ee_block: u32::from_le_bytes(data[0x0..0x4].try_into().unwrap()),
            ee_len: u16::from_le_bytes(data[0x4..0x6].try_into().unwrap()),
            ee_start: (ee_start_lo | (ee_start_hi << 16)) as usize,
        };
    }
}

impl Superblock {
    fn new(evidence: &mut Image, partition_offset: &usize) -> Superblock {
        evidence.seek(*partition_offset + 0x400);
        let data: Vec<u8> = evidence.read(0x3FD);

        let s_blocks_count_lo = u32::from_le_bytes(data[0x4..0x8].try_into().unwrap()) as u64;
        let s_blocks_count_hi = u32::from_le_bytes(data[0x150..0x154].try_into().unwrap()) as u64;

        return Superblock {
            s_inodes_count: u32::from_le_bytes(data[0x0..0x4].try_into().unwrap()),
            s_blocks_count: (s_blocks_count_hi << 32) + s_blocks_count_lo,
            s_free_inodes_count: u32::from_le_bytes(data[0x10..0x14].try_into().unwrap()),
            s_first_data_block: u32::from_le_bytes(data[0x14..0x18].try_into().unwrap()),
            s_log_block_size: u32::from_le_bytes(data[0x18..0x1C].try_into().unwrap()),
            s_blocks_per_group: u32::from_le_bytes(data[0x20..0x24].try_into().unwrap()),
            s_inodes_per_group: u32::from_le_bytes(data[0x28..0x2C].try_into().unwrap()),
            s_mtime: u32::from_le_bytes(data[0x2C..0x30].try_into().unwrap()),
            s_wtime: u32::from_le_bytes(data[0x30..0x34].try_into().unwrap()),
            s_mnt_count: u16::from_le_bytes(data[0x34..0x36].try_into().unwrap()),
            s_magic: u16::from_le_bytes(data[0x38..0x3A].try_into().unwrap()),
            s_first_ino: u32::from_le_bytes(data[0x54..0x58].try_into().unwrap()),
            s_inode_size: u16::from_le_bytes(data[0x58..0x5A].try_into().unwrap()),
            s_block_group_nr: u16::from_le_bytes(data[0x5A..0x5C].try_into().unwrap()),
            s_feature_compat: u32::from_le_bytes(data[0x5C..0x60].try_into().unwrap()),
            s_feature_incompat: u32::from_le_bytes(data[0x60..0x64].try_into().unwrap()),
            s_volume_name: str::from_utf8(&data[0x78..0x88]).unwrap().to_owned(),
            s_last_mounted: str::from_utf8(&data[0x88..0xC8]).unwrap().to_owned(),
            s_desc_size: u16::from_le_bytes(data[0xFE..0x100].try_into().unwrap()),
        };
    }

    fn print_sp_info(&self) {
        println!("Magic: {:x}", self.s_magic);
        println!("Total Inode count: {:?}", self.s_inodes_count);
        println!("Total Block count : {:?}", self.s_blocks_count);
        println!("Free inode count: {:?}", self.s_free_inodes_count);
        println!("First data block: {:?}", self.s_first_data_block);
        println!("Block size: {:?}", self.block_size());
        println!("Block per group: {:?}", self.s_blocks_per_group);
        println!("Inode per group: {:?}", self.s_inodes_per_group);
        println!("Block group size: {:?}", self.block_group_size());
        println!("Block group Count: {:?}", self.block_group_count());

        let mut dt = Utc.timestamp_opt(self.s_mtime.into(), 0).unwrap();
        println!("Mount time: {:?}", dt.to_rfc2822());
        dt = Utc.timestamp_opt(self.s_wtime.into(), 0).unwrap();
        println!("Write time: {:?}", dt.to_rfc2822());
        println!("Number of mounts : {:?}", self.s_mnt_count);
        println!("First non-reserved inode : 0x{:x}", self.s_first_ino);
        println!("Inode size in bytes : {:?}", self.s_inode_size);
        println!(
            "Block group # of this superblock : {:?}",
            self.s_block_group_nr
        );
        println!("Volume name : {}", self.s_volume_name);
        println!("Last mounted path : {}", self.s_last_mounted);
        println!("Size of group descriptors : {:?}", self.s_desc_size);

        println!("-----------------------------------------");
    }

    fn block_size(&self) -> usize {
        return 1024 << self.s_log_block_size as usize;
    }

    fn descriptor_size(&self) -> usize {
        return self.s_desc_size as usize;
    }

    fn block_group_count(&self) -> u64 {
        return self.s_blocks_count / self.s_blocks_per_group as u64;
    }

    fn block_group_size(&self) -> usize {
        return self.block_size() * self.s_blocks_per_group as usize;
    }
}

impl Inode {
    fn new(data: &[u8]) -> Inode {
        let i_size_lo = u32::from_le_bytes(data[0x4..0x8].try_into().unwrap()) as u64;
        let i_size_hi = u32::from_le_bytes(data[0x6C..0x70].try_into().unwrap()) as u64;
        let i_flags = u32::from_le_bytes(data[0x20..0x24].try_into().unwrap());

        return Inode {
            i_mode: u16::from_le_bytes(data[0x0..0x2].try_into().unwrap()),
            i_uid: u16::from_le_bytes(data[0x2..0x4].try_into().unwrap()),
            i_size: i_size_lo | (i_size_hi << 32),
            i_atime: u32::from_le_bytes(data[0x8..0xC].try_into().unwrap()),
            i_ctime: u32::from_le_bytes(data[0xC..0x10].try_into().unwrap()),
            i_mtime: u32::from_le_bytes(data[0x10..0x14].try_into().unwrap()),
            i_dtime: u32::from_le_bytes(data[0x14..0x18].try_into().unwrap()),
            i_gid: u16::from_le_bytes(data[0x18..0x1A].try_into().unwrap()),
            i_links_count: u16::from_le_bytes(data[0x1A..0x1C].try_into().unwrap()),
            i_block: data[0x28..0x64].to_vec(),
            i_flags,
            i_generation: u32::from_le_bytes(data[0x64..0x68].try_into().unwrap()),
            i_ctime_extra: u32::from_le_bytes(data[0x84..0x88].try_into().unwrap()),
            i_mtime_extra: u32::from_le_bytes(data[0x88..0x8C].try_into().unwrap()),
            i_atime_extra: u32::from_le_bytes(data[0x8C..0x90].try_into().unwrap()),
            i_crtime: u32::from_le_bytes(data[0x90..0x94].try_into().unwrap()),
            i_crtime_extra: u32::from_le_bytes(data[0x94..0x98].try_into().unwrap()),
            i_version_hi: u32::from_le_bytes(data[0x98..0x9C].try_into().unwrap()),
        };
    }

    fn is_dir(&self) -> bool {
        return (self.i_mode & 0x4000) != 0;
    }

    fn print_info(&self) {
        let atime = Utc.timestamp_opt(self.i_atime.into(), self.i_atime_extra);
        let ctime = Utc.timestamp_opt(self.i_ctime.into(), self.i_ctime_extra);
        let mtime = Utc.timestamp_opt(self.i_mtime.into(), self.i_mtime_extra);
        let dtime = Utc.timestamp_opt(self.i_dtime.into(), 0);
        let crtime = Utc.timestamp_opt(self.i_crtime.into(), self.i_crtime_extra);

        println!(
            "---------INODE---------
        Mode {:x}
        UUID : {:?}
        Size : {:?}
        File creation time: {:?}
        Last access time: {:?}
        Last data modification time : {:?}
        Deletion time {:?}
        Gid : {:?}
        Link count : {:?}
        Flags : {:?}
        Generation : {:?}
        Version : {:?}",
            self.i_mode,
            self.i_uid,
            self.i_size,
            crtime,
            atime,
            mtime,
            dtime,
            self.i_gid,
            self.i_links_count,
            self.i_flags,
            self.i_generation,
            self.i_version_hi
        );
    }
}

impl ExtentHeader {
    fn new(data: &Vec<u8>) -> ExtentHeader {
        let eh_magic = u16::from_le_bytes(data[0x0..0x2].try_into().unwrap());
        //println!("eh_magic : {:x}", eh_magic);
        return ExtentHeader {
            eh_magic,
            eh_entries: u16::from_le_bytes(data[0x2..0x4].try_into().unwrap()),
            eh_max: u16::from_le_bytes(data[0x4..0x6].try_into().unwrap()),
            eh_depth: u16::from_le_bytes(data[0x6..0x8].try_into().unwrap()),
        };
    }

    fn is_leaf(&self) -> bool {
        return self.eh_depth == 0;
    }

    fn is_index(&self) -> bool {
        return self.eh_depth != 0;
    }

    fn print_info(&self) {
        println!("Number of entries {}", self.eh_entries);
    }
}

impl ExtFS<'_> {
    pub fn new<'a>(
        evidence: &'a mut Image,
        partition: &'a mut VPartition,
    ) -> Result<ExtFS<'a>, String> {
        let superblock = Superblock::new(evidence, &partition.get_first_byte());
        let fstype: Type;
        // Verify it is indeed an extfs.
        if superblock.s_magic != EXT_MAGIC {
            return Err("Invalid FileSystem".to_string());
        }

        if superblock.s_blocks_per_group == 0 || superblock.s_inodes_per_group == 0 {
            return Err("Invalid FileSystem".to_string());
        }

        // If the files in this filesystem use extents -> Ext4 only
        if superblock.s_feature_incompat & INCOMPAT_EXTENTS != 0 {
            fstype = Type::Ext4;
        }
        // Ext3 is the ext2 filesystem enhanced with journalling capabilities.
        // So we check the journaling feature
        else if superblock.s_feature_compat & COMPAT_HAS_JOURNAL != 0 {
            fstype = Type::Ext3;
        }
        // Okay it's ext2 then..
        else {
            fstype = Type::Ext2;
        }

        return Ok(ExtFS {
            partition,
            superblock,
            fstype,
            evidence,
        });
    }

    fn bg_desc_offset(&self) -> usize {
        /* Get the group descriptor offset : | 1024 padding | superblock |.....| block group descriptors | ...
        ^ - Here                   */
        return self.partition.get_first_byte() + self.superblock.block_size();
    }

    pub fn print_info(&self) {
        self.superblock.print_sp_info();
    }

    fn get_itable_offset(&mut self, bg_desc_offset: usize) -> usize {
        self.evidence.seek(bg_desc_offset); // Seek to the right group descriptor.
        let bg_desc = self.evidence.read(self.superblock.s_desc_size as usize);

        // Parsing the inode table offset.
        // TODO : check if the Ext is using 64bit.
        let bg_inode_table_lo = u32::from_le_bytes(bg_desc[0x8..0xC].try_into().unwrap()) as u64;
        let bg_inode_table_hi = u32::from_le_bytes(bg_desc[0x28..0x2C].try_into().unwrap()) as u64;
        let bg_inode_table = ((bg_inode_table_hi << 32) | bg_inode_table_lo) as usize;
        let inode_table_offset = bg_inode_table * self.superblock.block_size(); // The inode table offset relative to the ext4 partition.
        return inode_table_offset;
    }

    pub fn get_inode(&mut self, inum: usize) -> Inode {
        // Ref : https://docs.kernel.org/filesystems/ext4/dynamic.html#index-nodes
        if inum == 0 {
            // Manage errors.
            panic!("There is no inode '0'");
        }
        // Get the group number and the inode_position in the group.
        let bg_num: usize = (inum - 1) / self.superblock.s_inodes_per_group as usize;
        let inode_index = (inum - 1) % self.superblock.s_inodes_per_group as usize;
        // Get the block group description offset
        let bg_desc_offset =
            self.bg_desc_offset() + (self.superblock.s_desc_size as usize * bg_num);
        // Parse the group descriptor and get the inode table offset.
        let inode_table_offset = self.get_itable_offset(bg_desc_offset);

        let inode_offset = self.partition.get_first_byte()
            + inode_table_offset
            + inode_index * self.superblock.s_inode_size as usize;
        self.evidence.seek(inode_offset);

        let raw_inode = self.evidence.read(self.superblock.s_inode_size as usize);
        return Inode::new(&raw_inode);
    }

    // pub fn test(&mut self){

    // }

    pub fn build_system_tree(&mut self) {
        // STEP 1. Identify the root inode, which is inode #2.
        let root_inode_num = 2;
        let inode = self.get_inode(root_inode_num);
        inode.print_info();
        // STEP 2. Retrieve the directory entry list associated with the root inode.
        let extend = ExtentHeader::new(&inode.i_block); // TODO check the magic number to see if it is indeed extend header.
        if extend.is_leaf() {
            let leaf = ExtentLeaf::new(&inode.i_block[0xC..0xC + 12].to_vec());
            let offset = leaf.ee_start * self.superblock.block_size();
            if inode.is_dir() {
                self.evidence.seek(self.partition.get_first_byte() + offset);
                let raw_entry = self.evidence.read(self.superblock.block_size() - 12);
                let mut j = 0;

                while j < raw_entry.len() {
                    let dir_entry =
                        DirEntry::new(&raw_entry[j..].to_vec(), self.superblock.s_feature_incompat);
                    dir_entry.print_info();
                    if dir_entry.rec_len == 0 {
                        break;
                    }
                    j += dir_entry.rec_len as usize;
                }
            }
        }
    }
}
