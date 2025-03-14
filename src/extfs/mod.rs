use std::error::Error;
use std::io::{Read, Seek, SeekFrom};
use std::str;

pub mod groupdescriptor;
pub mod inode;
pub mod superblock;

use groupdescriptor::GroupDescriptor;
use inode::Inode;
use superblock::Superblock;

const INCOMPAT_FILETYPE: u32 = 0x2;
const INCOMPAT_EXTENTS: u32 = 0x40; // typical ext4 incompat flag for extents
const EXT4_EXTENTS_FL: u32 = 0x00080000; // i_flags bit for extents
const EXT4_INLINE_DATA_FL: u32 = 0x10000000; // i_flags bit for inline data (if enabled)

// For reference only; not strictly necessary for the logic here.
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
    pub superblock: Superblock,
    body: T,
}

#[derive(Debug)]
struct ExtentLeaf {
    ee_block: u32,
    ee_len: u16,
    ee_start: usize, // the physical block where this extent begins
}

#[derive(Debug)]
struct ExtentHeader {
    eh_magic: u16,
    eh_entries: u16,
    eh_max: u16,
    eh_depth: u16,
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

    fn is_valid(&self) -> bool {
        // Typical ext4 extent magic = 0xF30A
        self.eh_magic == 0xF30A
    }
}

pub struct DirEntry {
    pub inode: u32,
    pub rec_len: u16,
    pub file_type: u8,
    pub name: String,
}

impl DirEntry {
    fn from_bytes(data: &[u8], comp: u32) -> DirEntry {
        let mut name_len = 0usize;
        let mut ftype = 0u8;

        // If the filesystem has the 'filetype' incompat feature, name_len is 1 byte, followed by a
        // single file_type byte; otherwise name_len is in 2 bytes [6..8].
        if comp & INCOMPAT_FILETYPE != 0 {
            name_len = data[6] as usize;
            ftype = data[7];
        } else {
            name_len = u16::from_le_bytes(data[6..8].try_into().unwrap()) as usize;
        }

        DirEntry {
            inode: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            rec_len: u16::from_le_bytes(data[4..6].try_into().unwrap()),
            file_type: ftype,
            name: String::from_utf8_lossy(&data[8..8 + name_len]).to_string(),
        }
    }

    pub fn print_info(&self) {
        if !self.name.is_empty() {
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

impl<T: Read + Seek> ExtFS<T> {
    /// Create a new ExtFS instance given any type that implements `Read` and `Seek`.
    pub fn new(mut body: T) -> Result<Self, String> {
        // Read the superblock at offset 0x400
        body.seek(SeekFrom::Start(0x400))
            .map_err(|e| e.to_string())?;
        let mut sp_data = vec![0u8; 0x400];
        body.read_exact(&mut sp_data).map_err(|e| e.to_string())?;

        let superblock = match Superblock::from_bytes(&sp_data) {
            Ok(sb) => sb,
            Err(message) => {
                eprintln!("{:?}", message);
                return Err(message);
            }
        };

        Ok(ExtFS { superblock, body })
    }

    /// Returns the offset where group descriptors start.
    fn bg_desc_offset(&self) -> u64 {
        let bs = self.superblock.block_size();
        // If the filesystem block size is 1 KiB, group desc table is at 2048.
        // Otherwise (2 KiB, 4 KiB, etc.), the group desc table is at the next block.
        if bs == 1024 {
            2048
        } else {
            bs
        }
    }

    // -- 1. Read a Group Descriptor by index. --
    fn read_group_descriptor(
        &mut self,
        group_index: u64,
    ) -> Result<GroupDescriptor, Box<dyn Error>> {
        let desc_size = self.superblock.descriptor_size();
        let offset = self.bg_desc_offset() + (group_index as u64) * (desc_size as u64);

        // Seek and read desc_size bytes
        self.body.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; desc_size];
        self.body.read_exact(&mut buf)?;

        let has_64bit = self.superblock.is_64bit();
        let gd = GroupDescriptor::from_bytes(&buf, has_64bit);
        Ok(gd)
    }

    // Read a particular inode by number.
    pub fn get_inode(&mut self, inode_num: u64) -> Result<Inode, Box<dyn Error>> {
        if inode_num < 1 || inode_num > self.superblock.s_inodes_count {
            return Err(format!("Inode {} out of valid range", inode_num).into());
        }

        let inodes_per_group = self.superblock.inodes_per_group() as u64;
        let group_index = (inode_num - 1) / inodes_per_group;
        let index_within_group = (inode_num - 1) % inodes_per_group;

        // Read the group descriptor
        let gd = self.read_group_descriptor(group_index)?;
        let inode_table_block = gd.bg_inode_table();
        let inode_table_offset = (inode_table_block as u64) * self.superblock.block_size()
            + (index_within_group * (self.superblock.inode_size() as u64));

        // Read the inode data (128 or 256+ bytes, depending on FS settings)
        let isz = self.superblock.inode_size();
        let mut buf = vec![0u8; isz];
        self.body.seek(SeekFrom::Start(inode_table_offset))?;
        self.body.read_exact(&mut buf)?;

        // Parse the inode
        let inode = Inode::from_bytes(&buf, isz as u64);
        Ok(inode)
    }

    // Helper to read one filesystem block into a Vec.
    fn read_block(&mut self, block_num: u64) -> Result<Vec<u8>, Box<dyn Error>> {
        if block_num >= self.superblock.blocks_count() {
            return Err(format!("Requested block {} is out of range", block_num).into());
        }
        let block_size = self.superblock.block_size();
        let offset = block_num * block_size;

        let mut buf = vec![0u8; block_size as usize];
        self.body.seek(SeekFrom::Start(offset))?;
        self.body.read_exact(&mut buf)?;
        Ok(buf)
    }

    // Parse extents (if i_block uses extents) to collect all runs as (logical_block, physical_block, length).
    // We'll combine them later into full block lists, if needed.
    fn parse_extents(&mut self, inode: &Inode) -> Result<Vec<(u64, u64, u64)>, Box<dyn Error>> {
        // The first 12 bytes of i_block contain the ExtentHeader if extents are used
        let mut raw_header = [0u8; 12];
        // copy from i_block into raw_header
        let i_block_bytes = {
            let mut tmp = vec![0u8; 60];
            for (i, &blk) in inode.block_pointers().iter().enumerate() {
                tmp[i * 4..i * 4 + 4].copy_from_slice(&blk.to_le_bytes());
            }
            tmp
        };
        raw_header.copy_from_slice(&i_block_bytes[0..12]);

        let eh = ExtentHeader::from_bytes(&raw_header);
        if !eh.is_valid() {
            return Err("Extent header invalid; cannot parse extents".into());
        }

        let mut extents_info = Vec::new();

        // Recursive function to parse an extent node.
        fn parse_extent_node<T: Read + Seek>(
            fs: &mut ExtFS<T>,
            block_num: u64,
            depth: u16,
        ) -> Result<Vec<ExtentLeaf>, Box<dyn Error>> {
            let block_data = fs.read_block(block_num)?;
            let header = ExtentHeader::from_bytes(&block_data[0..8]);
            if !header.is_valid() {
                return Err("Invalid extent header in parse_extent_node".into());
            }

            let entries = header.eh_entries as usize;
            let mut leaves = Vec::new();

            if header.is_leaf() {
                // parse direct extents
                let mut offset = 12;
                for _ in 0..entries {
                    let e = ExtentLeaf::from_bytes(&block_data[offset..offset + 12]);
                    offset += 12;
                    leaves.push(e);
                }
            } else {
                // parse indexes, then recurse
                let mut offset = 12;
                for _ in 0..entries {
                    let idx = ExtentIndex::from_bytes(&block_data[offset..offset + 12]);
                    offset += 12;
                    let child_leaves = parse_extent_node(fs, idx.leaf(), depth - 1)?;
                    leaves.extend(child_leaves);
                }
            }
            Ok(leaves)
        }

        // If eh_depth=0, extents are inline in i_block
        if eh.is_leaf() {
            let entries = eh.eh_entries as usize;
            let mut offset = 12;
            let mut leaves = Vec::new();
            // Use the 60 bytes in i_block_bytes
            for _ in 0..entries {
                let e = ExtentLeaf::from_bytes(&i_block_bytes[offset..offset + 12]);
                offset += 12;
                leaves.push(e);
            }
            for lf in leaves {
                extents_info.push((lf.ee_block as u64, lf.ee_start as u64, lf.ee_len as u64));
            }
        } else {
            // We have an extent tree
            let entries = eh.eh_entries as usize;
            let mut offset = 12;
            let mut idxs = Vec::new();
            for _ in 0..entries {
                let idx = ExtentIndex::from_bytes(&i_block_bytes[offset..offset + 12]);
                offset += 12;
                idxs.push(idx);
            }
            for idx in idxs {
                let child_leaves = parse_extent_node(self, idx.leaf(), eh.eh_depth - 1)?;
                for lf in child_leaves {
                    extents_info.push((lf.ee_block as u64, lf.ee_start as u64, lf.ee_len as u64));
                }
            }
        }

        Ok(extents_info)
    }

    // -------------------------------------------------------------------------
    // Helper methods to handle old-style indirect/double-indirect/triple-indirect blocks.
    // -------------------------------------------------------------------------

    /// Read a block of 4-byte pointers from an indirect block, returning them in a Vec.
    fn read_indirect_block_pointers(&mut self, block_num: u64) -> Result<Vec<u64>, Box<dyn Error>> {
        let block_data = self.read_block(block_num)?;
        let mut pointers = Vec::new();
        // Each pointer is 4 bytes, in little-endian
        let step = 4;
        for chunk in block_data.chunks(step) {
            if chunk.len() < 4 {
                break;
            }
            let ptr = u32::from_le_bytes(chunk.try_into().unwrap()) as u64;
            pointers.push(ptr);
        }
        Ok(pointers)
    }

    /// Recursively collect the block numbers from an indirect node at the given level.
    /// level=1 => singly-indirect, level=2 => doubly-indirect, level=3 => triply-indirect.
    fn collect_indirect_blocks(
        &mut self,
        block_num: u64,
        level: u32,
        results: &mut Vec<u64>,
    ) -> Result<(), Box<dyn Error>> {
        // Read this block of pointers
        let pointers = self.read_indirect_block_pointers(block_num)?;
        if level == 1 {
            // singly-indirect => each pointer is a data block
            for &blk in pointers.iter() {
                if blk != 0 {
                    results.push(blk);
                }
            }
        } else {
            // For each pointer, read the next level
            for &blk in pointers.iter() {
                if blk != 0 {
                    self.collect_indirect_blocks(blk, level - 1, results)?;
                }
            }
        }
        Ok(())
    }

    /// Gather all old-style block numbers for this inode (direct, single-indirect, double-indirect, triple-indirect).
    /// This ignores extent-based layouts. If the file is large or the pointers are zero, we skip them.
    fn collect_old_style_blocks(&mut self, inode: &Inode) -> Result<Vec<u64>, Box<dyn Error>> {
        let mut blocks = Vec::new();
        // Direct pointers [0..11]
        for i in 0..12 {
            let b = inode.block_pointers()[i];
            if b != 0 {
                blocks.push(b as u64);
            }
        }
        // i_block[12] => singly-indirect
        let singly = inode.block_pointers()[12];
        if singly != 0 {
            self.collect_indirect_blocks(singly as u64, 1, &mut blocks)?;
        }
        // i_block[13] => doubly-indirect
        let doubly = inode.block_pointers()[13];
        if doubly != 0 {
            self.collect_indirect_blocks(doubly as u64, 2, &mut blocks)?;
        }
        // i_block[14] => triply-indirect
        let triply = inode.block_pointers()[14];
        if triply != 0 {
            self.collect_indirect_blocks(triply as u64, 3, &mut blocks)?;
        }
        Ok(blocks)
    }

    // -------------------------------------------------------------------------
    // 3. Read the content of a file (or directory) from the given inode.
    // -------------------------------------------------------------------------
    pub fn read_inode(&mut self, inode: &Inode) -> Result<Vec<u8>, Box<dyn Error>> {
        // Corner case #1: Small symlink content is stored in i_block if the symlink is short.
        // For ext4, if inode.is_symlink() and size < 60, the symlink target is in i_block directly:
        if inode.is_symlink() {
            let sz = inode.size() as usize;
            // In Classic ext2/3/4, if the symlink is short enough to fit in i_block, the data is there:
            if sz < 60 {
                // Copy the raw bytes out of i_block
                let mut symlink_data = Vec::new();
                symlink_data.resize(sz, 0u8);
                let i_block_as_bytes = {
                    let mut tmp = vec![0u8; 60];
                    for (i, &blk) in inode.block_pointers().iter().enumerate() {
                        tmp[i * 4..i * 4 + 4].copy_from_slice(&blk.to_le_bytes());
                    }
                    tmp
                };
                symlink_data.copy_from_slice(&i_block_as_bytes[0..sz]);
                return Ok(symlink_data);
            }
        }

        // Corner case #2: Inline data (EXT4_INLINE_DATA_FL). If the filesystem + inode actually
        // supports it, the first bytes are in i_block. For demonstration, we show a simple approach:
        if (inode.flag() & EXT4_INLINE_DATA_FL) != 0 {
            // NOTE: Real ext4 inline data uses special structures in the i_block area. Here we do
            // a minimal approach: take min(inode.size(), 60) from i_block as data:
            let inline_sz = std::cmp::min(60, inode.size() as usize);
            let mut inline_data = Vec::new();
            inline_data.resize(inline_sz, 0);
            let i_block_as_bytes = {
                let mut tmp = vec![0u8; 60];
                for (i, &blk) in inode.block_pointers().iter().enumerate() {
                    tmp[i * 4..i * 4 + 4].copy_from_slice(&blk.to_le_bytes());
                }
                tmp
            };
            inline_data.copy_from_slice(&i_block_as_bytes[0..inline_sz]);
            // If the inode is fully inline, that might be the entire data.
            // If not fully inline, we'd also read the remainder via direct/indirect or extents.
            // For now, we’ll assume the entire file is inline if the flag is set.
            // Adjust as needed if your FS supports partial inline data + extents.
            return Ok(inline_data);
        }

        // Normal read (regular file, big symlink, etc.). We read up to inode.size().
        let file_size = inode.size() as usize;
        let mut data = vec![0u8; file_size]; // pre-zeroed (covers sparse blocks)

        // Check if extents are used:
        let uses_extents = (inode.flag() & EXT4_EXTENTS_FL) != 0
            || (self.superblock.feature_incompat() & INCOMPAT_EXTENTS) != 0;

        if uses_extents {
            // For ext4 with extents, parse them.
            let extents = self.parse_extents(inode)?;
            let block_size = self.superblock.block_size() as usize;

            for (logical_blk, start_blk, length) in extents {
                let start_byte_in_file = (logical_blk as usize) * block_size;
                // read each block in the run:
                for i in 0..(length as usize) {
                    let file_offset = start_byte_in_file + i * block_size;
                    if file_offset >= file_size {
                        break;
                    }
                    if start_blk + i as u64 >= self.superblock.blocks_count() {
                        // out-of-range block => treat as sparse
                        continue;
                    }
                    let block_buf = self.read_block(start_blk + i as u64)?;
                    let copy_len = std::cmp::min(block_size, file_size - file_offset);
                    data[file_offset..file_offset + copy_len]
                        .copy_from_slice(&block_buf[0..copy_len]);
                }
            }
        } else {
            // Old-style block pointers: handle direct + single/double/triple indirect
            let blocks = self.collect_old_style_blocks(inode)?;
            let block_size = self.superblock.block_size() as usize;
            // The file’s logical blocks are in [0..blocks.len())
            for (i, &blk) in blocks.iter().enumerate() {
                let file_offset = i * block_size;
                if file_offset >= file_size {
                    break;
                }
                if blk == 0 || blk >= self.superblock.blocks_count() {
                    // If pointer=0 (sparse) or out-of-range, leave that region at 0
                    continue;
                }
                let block_buf = self.read_block(blk)?;
                let copy_len = std::cmp::min(block_size, file_size - file_offset);
                data[file_offset..file_offset + copy_len].copy_from_slice(&block_buf[0..copy_len]);
            }
        }

        Ok(data)
    }

    // -- 4. List the directory entries for a directory inode. --
    pub fn list_dir(&mut self, inode: &Inode) -> Result<Vec<DirEntry>, Box<dyn Error>> {
        if !inode.is_dir() {
            return Err("Not a directory inode".into());
        }
        let dir_data = self.read_inode(inode)?;
        let mut entries = Vec::new();
        let mut offset = 0usize;
        let fs_feature_incompat = self.superblock.feature_incompat();

        while offset + 8 <= dir_data.len() {
            // minimum size for a dir entry is 8 bytes
            let rec_len =
                u16::from_le_bytes(dir_data[offset + 4..offset + 6].try_into().unwrap()) as usize;
            if rec_len == 0 {
                break;
            }
            if offset + rec_len > dir_data.len() {
                break;
            }
            let entry =
                DirEntry::from_bytes(&dir_data[offset..offset + rec_len], fs_feature_incompat);
            if entry.inode == 0 {
                // Entry might have been deleted or is just padding
                offset += rec_len;
                continue;
            }
            entries.push(entry);
            offset += rec_len;
        }

        Ok(entries)
    }

    // Resolve a path from root (inode 2) and read the file’s bytes.
    // Returns error if any path component is missing or is not a directory when expected, etc.
    pub fn read_file_by_path(&mut self, path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        // Normalize path
        let parts = path
            .split('/')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>();

        // Start from root inode (2)
        let mut current_inode = self.get_inode(2)?;

        for (i, part) in parts.iter().enumerate() {
            if !current_inode.is_dir() {
                return Err(format!("'{}' is not a directory in path", part).into());
            }
            // find part in directory
            let entries = self.list_dir(&current_inode)?;
            let mut found = false;
            let mut next_inode_num = 0;
            for de in entries {
                if de.name == *part {
                    found = true;
                    next_inode_num = de.inode as u64;
                    break;
                }
            }
            if !found {
                return Err(format!("Path component '{}' not found", part).into());
            }
            let next_inode = self.get_inode(next_inode_num)?;
            current_inode = next_inode;

            if i == parts.len() - 1 {
                // last component => read the file content
                if current_inode.is_regular_file() || current_inode.is_symlink() {
                    return self.read_inode(&current_inode);
                } else if current_inode.is_dir() {
                    return Err(format!("'{}' is a directory, not a file", part).into());
                } else {
                    return Err(format!("'{}' is not a regular file or symlink", part).into());
                }
            }
        }

        Err("No file found; maybe the path was empty or ended with a directory".into())
    }
}
