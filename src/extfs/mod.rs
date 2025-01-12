mod groupdescriptor;
mod inode;
mod superblock;
use exhume_body::Body;
use groupdescriptor::GroupDescriptor;
use inode::Inode;
use std::str;
use superblock::Superblock;
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

pub struct ExtFS<'a> {
    start_byte_address: &'a usize,
    pub superblock: Superblock,
    body: &'a mut Body,
    group_descriptors: Option<Vec<GroupDescriptor>>,
}

struct ExtentLeaf {
    ee_block: u32,
    ee_len: u16,
    ee_start: usize,
}

struct ExtentHeader {
    eh_magic: u16,
    eh_entries: u16,
    eh_max: u16,
    eh_depth: u16,
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
            0x1 => _FileType::Regular,
            0x2 => _FileType::Directory,
            0x3 => _FileType::Character,
            0x4 => _FileType::Block,
            0x5 => _FileType::FIFO,
            0x6 => _FileType::Socket,
            0x7 => _FileType::Symbolic,
            _ => _FileType::Unknown,
        }
    }

    fn new(data: &Vec<u8>, comp: u32) -> DirEntry {
        let name_len: usize;
        let ftype: u8;
        if comp & INCOMPAT_FILETYPE != 0 {
            // "filetype" feature flag is set -> ext4_dir_entry_2
            name_len = data[0x6] as usize;
            ftype = data[0x7];
        } else {
            // -> ext4_dir_entry
            name_len = u16::from_le_bytes(data[0x6..0x8].try_into().unwrap()) as usize;
            ftype = 0x0; // Unknown.
        }

        DirEntry {
            inode: u32::from_le_bytes(data[0x0..0x4].try_into().unwrap()),
            rec_len: u16::from_le_bytes(data[0x4..0x6].try_into().unwrap()),
            file_type: ftype,
            name: str::from_utf8(&data[0x8..0x8 + name_len])
                .unwrap()
                .to_owned(),
        }
    }

    fn print_info(&self) {
        if self.name.len() > 0 {
            println!("{} :  {} : 0x{:x}", self.inode, self.name, self.file_type);
        }
    }
}

impl ExtentLeaf {
    fn new(data: &[u8]) -> ExtentLeaf {
        let ee_start_hi = u16::from_le_bytes(data[0x6..0x8].try_into().unwrap()) as u32;
        let ee_start_lo = u32::from_le_bytes(data[0x8..0xC].try_into().unwrap());
        ExtentLeaf {
            ee_block: u32::from_le_bytes(data[0x0..0x4].try_into().unwrap()),
            ee_len: u16::from_le_bytes(data[0x4..0x6].try_into().unwrap()),
            ee_start: (ee_start_lo | (ee_start_hi << 16)) as usize,
        }
    }
}

impl ExtentHeader {
    fn new(data: &[u8]) -> ExtentHeader {
        let eh_magic = u16::from_le_bytes(data[0x0..0x2].try_into().unwrap());
        ExtentHeader {
            eh_magic,
            eh_entries: u16::from_le_bytes(data[0x2..0x4].try_into().unwrap()),
            eh_max: u16::from_le_bytes(data[0x4..0x6].try_into().unwrap()),
            eh_depth: u16::from_le_bytes(data[0x6..0x8].try_into().unwrap()),
        }
    }

    fn is_leaf(&self) -> bool {
        self.eh_depth == 0
    }

    fn is_index(&self) -> bool {
        self.eh_depth != 0
    }

    fn print_info(&self) {
        println!("Number of entries {}", self.eh_entries);
    }
}

impl<'a> ExtFS<'a> {
    pub fn new(body: &'a mut Body, start_byte_address: &'a usize) -> Result<ExtFS<'a>, String> {
        body.seek(*start_byte_address + 0x400);

        let superblock = match Superblock::from_bytes(&body.read(0x400)) {
            Ok(superblock) => superblock,
            Err(message) => {
                eprintln!("{:?}", message);
                std::process::exit(1);
            }
        };

        Ok(ExtFS {
            start_byte_address,
            superblock,
            body,
            group_descriptors: None,
        })
    }

    /// Get the Block Group descriptor address in the given body of data
    /// | 1024 padding | superblock |.....| block group descriptors | ...
    ///___________________________________^ - Here
    fn bg_desc_offset(&self) -> usize {
        return self.start_byte_address + 1024 + self.superblock.block_size(); // address of the partition + 1024 padding + 1 block = The address of the block group descriptors.
    }

    /// Load all of the group descriptors into an existing Extfs struct
    pub fn load_group_descriptors(&mut self) -> Result<(), String> {
        // Calculate fundamental parameters
        let block_size = self.superblock.block_size() as u64;
        let blocks_count = self.superblock.blocks_count() as u64;
        let blocks_per_group = self.superblock.blocks_per_group() as u64;

        // Number of groups in the filesystem
        let num_groups = (blocks_count + (blocks_per_group - 1)) / blocks_per_group;

        // Each older-style group descriptor is 32 bytes.
        // The table might span multiple blocks if there are many groups.
        let gd_size = if self.superblock.is_64bit() { 64 } else { 32 };
        let total_gd_bytes = (num_groups as usize) * gd_size;
        let blocks_needed = (total_gd_bytes + (block_size as usize - 1)) / block_size as usize;

        // Seek in your Body to the start of the group descriptor table
        self.body.seek(self.bg_desc_offset());
        // Read all the descriptor data
        let buffer = self.body.read(blocks_needed * block_size as usize);

        // Now parse each group descriptor
        let mut group_descs = Vec::with_capacity(num_groups as usize);
        for i in 0..num_groups {
            let offset = (i as usize) * gd_size;
            let chunk = &buffer[offset..offset + gd_size];
            let gd = GroupDescriptor::from_bytes(chunk, self.superblock.is_64bit());
            group_descs.push(gd);
        }

        // Store them in the ExtFS struct
        //println!("{:#?}", group_descs);
        self.group_descriptors = Some(group_descs);
        Ok(())
    }

    /// Retrive all of the block descriptors
    pub fn get_bg_descriptors(&self) -> Result<&Vec<GroupDescriptor>, String> {
        let group_descs = match &self.group_descriptors {
            Some(gds) => Ok(gds),
            None => Err("Group descriptors are not loaded.".to_string()),
        };
        group_descs
    }

    /// Retrieve the inode with the given `inode_num`.
    ///
    /// - Finds which block group this inode belongs to.
    /// - Determines the offset in the inode table.
    /// - Seeks in the `Body` to that offset and reads the raw inode bytes.
    /// - Parses them with `Inode::from_bytes`.
    pub fn get_inode(&mut self, inode_num: u32) -> Result<Inode, String> {
        // Ensure group descriptors are loaded
        let group_descs = match &self.group_descriptors {
            Some(gds) => gds,
            None => return Err("Group descriptors are not loaded.".to_string()),
        };

        let inodes_per_group = self.superblock.inodes_per_group() as u32;
        let inode_size = self.superblock.inode_size() as u64; // e.g. 128 or 256
        let block_size = self.superblock.block_size() as u64;

        // Which block group?
        // In ext4, inodes are numbered starting at 1, so offset by -1
        let block_group = (inode_num - 1) / inodes_per_group;
        let index_within_group = (inode_num - 1) % inodes_per_group;

        // The group descriptor for that block group
        let gd = &group_descs[block_group as usize];

        // The inode table starts at block `bg_inode_table_lo` (old layout).
        // For 64-bit capable layouts, you may need `bg_inode_table_hi` as well.
        let inode_table_start_block = gd.bg_inode_table();

        // Byte offset into inode table for our specific inode:
        let inode_byte_offset = (index_within_group as u64) * inode_size;

        // println!("inode_byte_offset  0x{:x}", inode_byte_offset);

        // The global byte offset in the filesystem image:
        //   = start of partition
        //   + (inode_table_start_block * block_size)
        //   + inode_byte_offset
        let global_byte_offset = (*self.start_byte_address as u64)
            + (inode_table_start_block * block_size)
            + inode_byte_offset;

        // println!("global_byte_offset  0x{:x}", global_byte_offset);

        // Now read the inode bytes
        self.body.seek(global_byte_offset as usize);
        // println!("Inode size:{:?}", inode_size);
        let inode_buf = self.body.read(inode_size as usize);
        // println!("{:?}", inode_buf);
        // Parse the inode structure
        let inode = Inode::from_bytes(&inode_buf, inode_size);
        // println!("{:#?}", inode);
        Ok(inode)
    }
}
