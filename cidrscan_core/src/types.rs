//! Data structures for Patricia tree


use crate::shmem_rwlock::RawRwLock;
use std::mem::MaybeUninit;
use std::{
    ptr::NonNull,
    sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize},
    cell::Cell,
};
use shared_memory::Shmem;
use crossbeam_queue::SegQueue;
use std::sync::Arc;


/// Offset type: always 32 bits, portable across 32/64-bit platforms
pub type Offset = u32; // <= 4 294 967 295 bytes from base

/// Shared‑memory header (aligned to cache line)
#[repr(C, align(64))]
pub struct Header {
    pub magic: u64,             // identifies valid CIDRScan header
    pub version: u16,           // ABI version
    pub _reserved: [u8; 6],     // padding to 16 bytes total
    pub lock_init: AtomicU8,    // 0 = uninit, 1 = init (atomic process-local lock init flag)
    pub lock: MaybeUninit<RawRwLock>, // cross-process RW-lock (initialized in place)
    pub next_index: AtomicU32,  // bump allocator index for new allocations
    pub free_slots: AtomicU32,  // incremented on delete, decremented on alloc from freelist
    pub root_offset: AtomicU64, // atomic root pointer for lock‑free reads (ABA-safe)
    pub capacity: usize,        // max nodes in arena
    pub ref_count: AtomicUsize, // live-handle counter
    pub global_epoch: AtomicU64, // <── NEW: shared global epoch for GC
    pub init_flag: AtomicU32,   // 0 = un-initialised, 1 = ready
}

/// Node in the Patricia tree, each aligned to cache line
#[repr(C, align(64))]
pub struct Node {
    pub key: u128,      // IPv4 in upper 96 bits zero, or full IPv6
    pub prefix_len: u8, // valid bits in key
    pub _pad: [u8; 3],  // padding to align next atomics (adjusted for AtomicU32)
    /// ABA generation counter to prevent reuse hazards
    pub generation: AtomicU32, // ABA generation counter
    pub is_terminal: AtomicU8, // 0 = not stored; 1 = stored
    pub tag_off: AtomicU32,
    pub left: AtomicU64, // packed (offset, generation) to left child
    pub right: AtomicU64, // packed (offset, generation) to right child
    pub expires: AtomicU64, // Unix epoch seconds: TTL expiration
    pub refcnt: AtomicU32, // how many identical prefixes are stored
}

/// PatriciaTree struct (core handle)
pub struct PatriciaTree {
    pub shmem: Shmem,         // The shared memory mapping
    pub hdr: NonNull<Header>, // Pointer to header in shared memory
    pub base: NonNull<u8>,    // Base pointer for node offsets
    pub tag_base: NonNull<u8>, // start of tag slab
    pub os_id: String,        // Track the shared memory name for Drop
    pub freelist: Arc<SegQueue<Offset>>, // locally-owned queue of freed offsets
    pub local_epoch: Cell<u64>,          // <── NEW (std::cell::Cell)
}

// SAFETY: Even though PatriciaTree contains raw pointers (NonNull<u8>),
// it's safe to send between threads because:
// 1. The data it points to is in shared memory (Shmem)
// 2. Access is properly synchronized through Mutex locks
unsafe impl Send for PatriciaTree {}
unsafe impl Sync for PatriciaTree {}

// SAFETY: Even though PatriciaTree contains pointers to types with interior mutability (Mutex),
// we explicitly guarantee that panic unwinding is safe because:
// 1. We ensure proper cleanup and never leave the shared memory in a corrupted state during panics
// 2. The raw pointers themselves are stable and safe even across unwinding boundaries
impl std::panic::RefUnwindSafe for PatriciaTree {}
impl std::panic::UnwindSafe for PatriciaTree {}

pub struct Match<'a> {
    pub cidr_key: u128,
    pub plen: u8,
    pub tag: &'a str,
}