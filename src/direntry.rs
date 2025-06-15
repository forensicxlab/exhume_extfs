//! Directory‐entry helpers for an **ext4** filesystem.
//!
//! The on-disk layout is described in the upstream Linux documentation:
//! <https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html>

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

/// “File‐type present in directory entries” incompatibility bit in the super-block.
pub const INCOMPAT_FILETYPE: u32 = 0x2;

/// A single directory entry as stored on disk.
///
/// All numeric fields are little-endian in the ext4 format.
#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntry {
    /// Inode number associated with the directory entry.
    pub inode: u32,
    /// Length of this directory-entry record in bytes.
    pub rec_len: u16,
    /// On-disk file type (`0` if the `filetype` feature is disabled).
    pub file_type: u8,
    /// File name (bytes `[8..]`, UTF-8 lossily decoded).
    pub name: String,
}

impl DirEntry {
    /// Construct a [`DirEntry`] from a raw on-disk buffer.
    ///
    /// The slice **must** contain at least the first 8 bytes of an ext4 dirent.
    ///
    /// # Parameters
    ///
    /// * `data` – Raw bytes starting at the dirent.
    /// * `compat_flags` – The super-block’s `s_incompat_features` field; used
    ///   to decide whether a file-type byte is present.
    pub fn from_bytes(data: &[u8], compat_flags: u32) -> Self {
        let (name_len, file_type) = if compat_flags & INCOMPAT_FILETYPE != 0 {
            (data[6] as usize, data[7])
        } else {
            (
                u16::from_le_bytes(data[6..8].try_into().unwrap()) as usize,
                0,
            )
        };

        Self {
            inode: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            rec_len: u16::from_le_bytes(data[4..6].try_into().unwrap()),
            file_type,
            name: String::from_utf8_lossy(&data[8..8 + name_len]).to_string(),
        }
    }

    /// Serialise the entry as a [`serde_json::Value`].
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({}))
    }
}

impl fmt::Display for DirEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name.is_empty() {
            true => write!(f, "{} : ? : 0x{:x}", self.inode, self.file_type),
            false => write!(f, "{} : {} : 0x{:x}", self.inode, self.name, self.file_type),
        }
    }
}
