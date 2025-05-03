//! Constants and configuration for Patricia tree

#[cfg(target_os = "windows")]
pub const PREFIX: &str = "cidrscan_"; // No Global\ here
#[cfg(not(target_os = "windows"))]
pub const PREFIX: &str = "cidrscan_";

pub const FNV_OFFSET: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u64 = 0x100000001b3;

pub const CACHE_LINE: usize = 64;

// HEADER_PADDED depends on Header, which is defined in types.rs, so we declare it as a function here.
// The actual value should be computed in lib.rs after types are available, or you can move the calculation to types.rs if needed.

pub const DEFAULT_CAPACITY: usize = 1_048_576;

pub const HEADER_MAGIC: u64 = 0x434944525343414E; // "CIDRSCAN"
pub const HEADER_VERSION: u16 = 1;