use std::error::Error;
use std::io::{Read, Seek, SeekFrom};
use std::str;

mod groupdescriptor;
mod inode;
mod superblock;

use groupdescriptor::GroupDescriptor;
use inode::Inode;
use superblock::Superblock;

const INCOMPAT_FILETYPE: u32 = 0x2;

enum FileType {
    Unknown,
    Regular,
    Directory,
    Character,
    Block,
    FIFO,
    Socket,
    Symbolic,
}

#[derive(Debug)]
struct ExtentIndex {
    ei_block: u32,
    ei_leaf_lo: u32,
    ei_leaf_hi: u16,
    ei_unused: u16,
}

impl ExtentIndex {
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

    pub fn leaf(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | (self.ei_leaf_lo as u64)
    }
}

pub struct ExtFS<T: Read + Seek> {
    start_byte_address: u64,
    pub superblock: Superblock,
    body: T,
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

pub struct DirEntry {
    inode: u32,
    rec_len: u16,
    file_type: u8,
    name: String,
}

impl DirEntry {
    fn _get_file_type(&self) -> FileType {
        match self.file_type {
            0x1 => FileType::Regular,
            0x2 => FileType::Directory,
            0x3 => FileType::Character,
            0x4 => FileType::Block,
            0x5 => FileType::FIFO,
            0x6 => FileType::Socket,
            0x7 => FileType::Symbolic,
            _ => FileType::Unknown,
        }
    }

    fn from_bytes(data: &Vec<u8>, comp: u32) -> DirEntry {
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

    pub fn print_info(&self) {
        if self.name.len() > 0 {
            println!("{} :  {} : 0x{:x}", self.inode, self.name, self.file_type);
        }
    }
}

impl ExtentLeaf {
    fn from_bytes(data: &[u8]) -> ExtentLeaf {
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
    fn from_bytes(data: &[u8]) -> ExtentHeader {
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

impl<T: Read + Seek> ExtFS<T> {
    /// Create a new ExtFS instance given any type that implements `Read` and `Seek`
    pub fn new(mut body: T, start_byte_address: u64) -> Result<Self, String> {
        // Seek to the superblock location (1024 bytes of padding + 0x400)
        body.seek(SeekFrom::Start(start_byte_address + 0x400))
            .map_err(|e| e.to_string())?;
        let mut sp_data = vec![0u8; 0x400];
        body.read_exact(&mut sp_data).map_err(|e| e.to_string())?;

        let superblock = match Superblock::from_bytes(&sp_data) {
            Ok(sb) => sb,
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
    fn bg_desc_offset(&self) -> u64 {
        self.start_byte_address + 1024 + self.superblock.block_size()
    }

    /// Load all of the group descriptors into an existing ExtFS struct
    pub fn load_group_descriptors(&mut self) -> Result<(), String> {
        let block_size = self.superblock.block_size();
        let blocks_count = self.superblock.blocks_count();
        let blocks_per_group = self.superblock.blocks_per_group();

        let num_groups = (blocks_count + (blocks_per_group - 1)) / blocks_per_group;
        let gd_size = if self.superblock.is_64bit() { 64 } else { 32 };
        let total_gd_bytes = (num_groups as usize) * gd_size;
        let blocks_needed = (total_gd_bytes + (block_size as usize - 1)) / block_size as usize;

        self.body
            .seek(SeekFrom::Start(self.bg_desc_offset()))
            .map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; blocks_needed * block_size as usize];
        self.body
            .read_exact(&mut buffer)
            .map_err(|e| e.to_string())?;

        let mut group_descs = Vec::with_capacity(num_groups as usize);
        for i in 0..num_groups {
            let offset = (i as usize) * gd_size;
            let chunk = &buffer[offset..offset + gd_size];
            let gd = GroupDescriptor::from_bytes(chunk, self.superblock.is_64bit());
            group_descs.push(gd);
        }
        self.group_descriptors = Some(group_descs);
        Ok(())
    }

    /// Retrieve all of the block group descriptors.
    pub fn get_bg_descriptors(&self) -> Result<&Vec<GroupDescriptor>, String> {
        match &self.group_descriptors {
            Some(gds) => Ok(gds),
            None => Err("Group descriptors are not loaded.".to_string()),
        }
    }

    /// Retrieve the inode with the given `inode_num`.
    pub fn get_inode(&mut self, inode_num: u32) -> Result<Inode, String> {
        let group_descs = self
            .group_descriptors
            .as_ref()
            .ok_or_else(|| "Group descriptors are not loaded.".to_string())?;

        let inodes_per_group = self.superblock.inodes_per_group() as u32;
        let inode_size = self.superblock.inode_size() as u64;
        let block_size = self.superblock.block_size() as u64;

        let block_group = (inode_num - 1) / inodes_per_group;
        let index_within_group = (inode_num - 1) % inodes_per_group;
        let gd = &group_descs[block_group as usize];

        let inode_table_start_block = gd.bg_inode_table();
        let inode_byte_offset = (index_within_group as u64) * inode_size;
        let global_byte_offset =
            self.start_byte_address + (inode_table_start_block * block_size) + inode_byte_offset;

        let mut inode_buf = vec![0u8; inode_size as usize];
        self.body
            .seek(SeekFrom::Start(global_byte_offset))
            .map_err(|e| e.to_string())?;
        self.body
            .read_exact(&mut inode_buf)
            .map_err(|e| e.to_string())?;

        let inode = Inode::from_bytes(&inode_buf, inode_size);
        Ok(inode)
    }

    pub fn read(&mut self, inode_num: u32) -> Result<Vec<u8>, Box<dyn Error>> {
        let inode = self.get_inode(inode_num)?;
        let size = inode.size() as usize;
        let bs = self.superblock.block_size() as usize;
        let blocks = self.get_file_blocks(&inode)?;
        let mut data = Vec::with_capacity(size);
        for blk in blocks {
            let offs = self.start_byte_address + (blk as u64 * bs as u64);
            self.body.seek(SeekFrom::Start(offs)).unwrap();
            let mut chunk = vec![0u8; bs];
            self.body.read_exact(&mut chunk).unwrap();
            data.append(&mut chunk);
        }
        data.truncate(size);
        Ok(data)
    }

    pub fn list_dir(&mut self, inode_num: u32) -> Result<Vec<DirEntry>, Box<dyn Error>> {
        let inode = self.get_inode(inode_num)?;
        if !inode.is_dir() {
            return Err(format!(
                "Inode {} is not a directory (mode=0o{:o})",
                inode_num,
                inode.mode()
            )
            .into());
        }
        let bytes = self.read(inode_num)?;
        let comp = self.superblock.feature_incompat();
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 8 <= bytes.len() {
            let rec_len = u16::from_le_bytes(bytes[pos + 4..pos + 6].try_into()?);
            if rec_len < 8 || pos + rec_len as usize > bytes.len() {
                break;
            }
            let slice = &bytes[pos..(pos + rec_len as usize)];
            let dentry = DirEntry::from_bytes(&slice.to_vec(), comp);
            if dentry.inode != 0 {
                out.push(dentry);
            }
            pos += rec_len as usize;
        }
        Ok(out)
    }

    fn get_file_blocks(&mut self, inode: &Inode) -> Result<Vec<u32>, Box<dyn Error>> {
        if inode.flag() & 0x80000 != 0 {
            self.get_extent_blocks(inode)
        } else {
            self.get_classic_blocks(inode)
        }
    }

    fn get_classic_blocks(&mut self, inode: &Inode) -> Result<Vec<u32>, Box<dyn Error>> {
        let bs = self.superblock.block_size() as usize;
        let ptrs_per_block = bs / 4;
        let mut blocks = Vec::new();
        for i in 0..12 {
            if inode.block_pointers()[i] == 0 {
                break;
            }
            blocks.push(inode.block_pointers()[i]);
        }
        if inode.block_pointers()[12] != 0 {
            blocks.extend(self.read_indirect_block(inode.block_pointers()[12], ptrs_per_block)?);
        }
        if inode.block_pointers()[13] != 0 {
            let blk_nums_lvl1 =
                self.read_indirect_block(inode.block_pointers()[13], ptrs_per_block)?;
            for &b1 in &blk_nums_lvl1 {
                if b1 != 0 {
                    blocks.extend(self.read_indirect_block(b1, ptrs_per_block)?);
                }
            }
        }
        if inode.block_pointers()[14] != 0 {
            let blk_nums_lvl2 =
                self.read_indirect_block(inode.block_pointers()[14], ptrs_per_block)?;
            for &b2 in &blk_nums_lvl2 {
                if b2 != 0 {
                    let blk_nums_lvl1 = self.read_indirect_block(b2, ptrs_per_block)?;
                    for &b1 in &blk_nums_lvl1 {
                        if b1 != 0 {
                            blocks.extend(self.read_indirect_block(b1, ptrs_per_block)?);
                        }
                    }
                }
            }
        }
        Ok(blocks)
    }

    fn read_indirect_block(
        &mut self,
        block_num: u32,
        max_ptrs: usize,
    ) -> Result<Vec<u32>, Box<dyn Error>> {
        let bs = self.superblock.block_size() as usize;
        let offs = self.start_byte_address + (block_num as u64 * bs as u64);
        self.body.seek(SeekFrom::Start(offs)).unwrap();
        let mut raw = vec![0u8; bs];
        self.body.read_exact(&mut raw).unwrap();
        let mut out = Vec::new();
        for i in 0..max_ptrs {
            let begin = i * 4;
            let end = begin + 4;
            let ptr = u32::from_le_bytes(raw[begin..end].try_into()?);
            if ptr == 0 {
                break;
            }
            out.push(ptr);
        }
        Ok(out)
    }

    fn get_extent_blocks(&mut self, inode: &Inode) -> Result<Vec<u32>, Box<dyn Error>> {
        let bs = self.superblock.block_size() as usize;
        let i_block_bytes = unsafe {
            std::slice::from_raw_parts(
                inode.block_pointers().as_ptr() as *const u8,
                inode.block_pointers().len() * 4,
            )
        };
        let eh = ExtentHeader::from_bytes(i_block_bytes);
        if eh.eh_magic != 0xF30A {
            return Err("Invalid extent header magic".into());
        }
        let mut all_blocks = Vec::new();
        self.collect_extents(&eh, i_block_bytes, &mut all_blocks, 0, bs)?;
        Ok(all_blocks)
    }

    fn collect_extents(
        &mut self,
        eh: &ExtentHeader,
        data: &[u8],
        out: &mut Vec<u32>,
        level: u16,
        bs: usize,
    ) -> Result<(), Box<dyn Error>> {
        if eh.is_leaf() {
            let ext_sz = 12;
            let mut idx = 8;
            for _ in 0..eh.eh_entries {
                if idx + ext_sz > data.len() {
                    break;
                }
                let leaf = ExtentLeaf::from_bytes(&data[idx..idx + ext_sz]);
                idx += ext_sz;
                if leaf.ee_len > 0 {
                    for b in 0..(leaf.ee_len as u32) {
                        out.push(leaf.ee_start as u32 + b);
                    }
                }
            }
        } else {
            let idx_sz = 12;
            let mut idx = 8;
            for _ in 0..eh.eh_entries {
                if idx + idx_sz > data.len() {
                    break;
                }
                let idx_entry = ExtentIndex::from_bytes(&data[idx..idx + idx_sz]);
                idx += idx_sz;
                let block_num = idx_entry.leaf();
                let offset = self.start_byte_address + (block_num * bs as u64);
                self.body.seek(SeekFrom::Start(offset)).unwrap();
                let mut sub = vec![0u8; bs];
                self.body.read_exact(&mut sub).unwrap();
                let sub_eh = ExtentHeader::from_bytes(&sub[0..8]);
                self.collect_extents(&sub_eh, &sub, out, level + 1, bs)?;
            }
        }
        Ok(())
    }

    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut current_inode = 2;

        for (i, comp) in components.iter().enumerate() {
            let entries = self.list_dir(current_inode)?;

            let mut found = false;
            for e in entries {
                println!("{}", e.name);
                if e.name == *comp {
                    found = true;
                    if i == components.len() - 1 {
                        return self.read(e.inode);
                    } else {
                        if e.file_type != 0x2 {
                            return Err(format!("'{}' is not a directory", comp).into());
                        }
                        current_inode = e.inode;
                        break;
                    }
                }
            }

            if !found {
                return Err(format!("Path component '{}' not found", comp).into());
            }
        }

        Err("Path resolves to root or empty (no components)".into())
    }
}
