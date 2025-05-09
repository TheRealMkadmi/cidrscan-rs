//! Constants and configuration for Patricia tree

pub const PREFIX: &str = "cidrscan_"; // No Global\ here

pub const FNV_OFFSET: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;

pub const CACHE_LINE: usize = 64;
pub const TAG_MAX_LEN: usize = 32;

pub const DEFAULT_CAPACITY: usize = 1_048_576;

pub const HEADER_MAGIC: u64 = 0x434944525343414E; // "CIDRSCAN"
pub const HEADER_VERSION: u16 = 2;