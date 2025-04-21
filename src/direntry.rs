/// Reference: https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const INCOMPAT_FILETYPE: u32 = 0x2;

// Structure representing a directory entry
#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntry {
    // Inode number associated with the directory entry
    pub inode: u32,
    // Length of this directory entry record
    pub rec_len: u16,
    // Type of the file described by this directory entry
    pub file_type: u8,
    // Name of the file in the directory
    pub name: String,
}

impl DirEntry {
    /// Constructs a DirEntry from a byte slice and a compatibility flag
    ///
    /// # Arguments
    /// * `data` - A byte slice representing the raw directory entry data
    /// * `comp` - A u32 compatibility flag
    ///
    /// # Returns
    /// A DirEntry object populated from the given data
    pub fn from_bytes(data: &[u8], comp: u32) -> DirEntry {
        let name_len;
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
            // Extract the inode number from the first 4 bytes
            inode: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            // Extract the record length from bytes [4..6]
            rec_len: u16::from_le_bytes(data[4..6].try_into().unwrap()),
            // Assign the file type determined earlier
            file_type: ftype,
            // Extract the file name from bytes [8..8 + name_len] and convert it to a String
            name: String::from_utf8_lossy(&data[8..8 + name_len]).to_string(),
        }
    }

    pub fn to_string(&self) -> String {
        if !self.name.is_empty() {
            format!("{} :  {} : 0x{:x}", self.inode, self.name, self.file_type)
        } else {
            format!("{} :  ? : 0x{:x}", self.inode, self.file_type)
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}
