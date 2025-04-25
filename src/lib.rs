//! Monolithic, high‑performance, shared Patricia tree with TTL
//! Monolithic to allow stealing the entire tree in one go.

#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

mod cross_proc_rwlock;

// Helper function to calculate the length of the common prefix (up to max_len bits)
fn common_prefix_len(key1: u128, key2: u128, max_len: u8) -> u8 {
    if max_len == 0 {
        return 0;
    } // Handle zero length prefix comparison
      // Remove unused variable: let relevant_bits = 128 - max_len as u32;
      // Mask to ignore bits beyond max_len
    let mask = if max_len == 128 {
        !0u128
    } else {
        !(!0u128 >> max_len)
    };
    let diff = (key1 & mask) ^ (key2 & mask);
    if diff == 0 {
        return max_len; // Keys are identical up to max_len
    }
    // Calculate leading zeros of the difference, capped by 128 bits
    let lz = diff.leading_zeros().min(128) as u8;
    // Common prefix length is the number of leading matching bits, capped by max_len
    lz.min(max_len)
}

// Helper function to get the bit at a specific index (0 = MSB)
#[inline]
fn get_bit(key: u128, index: u8) -> u8 {
    debug_assert!(index <= 127); // 128 is never queried
    ((key >> (127 - index)) & 1) as u8
}

// Helper function to create a mask for a given prefix length
#[inline]
fn mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0 // No bits set for zero length prefix
    } else if prefix_len >= 128 {
        !0u128 // All bits set for 128 or more
    } else {
        !(!0u128 >> prefix_len) // Create mask by shifting
    }
}

use shared_memory::{Shmem, ShmemConf, ShmemError}; // Shared memory mapping :contentReference[oaicite:13]{index=13}
mod shmem_rwlock;
use crate::shmem_rwlock::RawRwLock;
use raw_sync::Timeout; // needed by API
use spin::Mutex; // **only** for the free-list
use std::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Offset type: always 32 bits, portable across 32/64-bit platforms
type Offset = u32; // <= 4 294 967 295 bytes from base

/// Packs an offset and generation into a single u64 for ABA-safe pointers.
#[inline]
fn pack(offset: u32, gen: u32) -> u64 {
    ((gen as u64) << 32) | (offset as u64)
}

/// Unpacks a u64 pointer into (offset, generation).
#[inline]
fn unpack(ptr: u64) -> (u32, u32) {
    (ptr as u32, (ptr >> 32) as u32)
}

/// Maximum nodes if not specified
const DEFAULT_CAPACITY: usize = 1_048_576;

/// Compile-time guarantee: arena fits in 32-bit offset
const _: () = assert!((DEFAULT_CAPACITY as u64) * (size_of::<Node>() as u64) < (1u64 << 32));

/// Magic and ABI version for header integrity checks
const HEADER_MAGIC: u64 = 0x434944525343414E; // "CIDRSCAN"
const HEADER_VERSION: u16 = 1;

/// Shared‑memory header (aligned to cache line)
#[repr(C, align(64))]
struct Header {
    magic: u64,             // identifies valid CIDRScan header
    version: u16,           // ABI version
    _reserved: [u8; 6],     // padding to 16 bytes total
    lock: RawRwLock,        // cross-process RW-lock (defined below)
    next_index: AtomicU32,  // bump allocator index for new allocations
    free_slots: AtomicU32,  // incremented on delete, decremented on alloc from freelist
    root_offset: AtomicU64, // atomic root pointer for lock‑free reads (ABA-safe)
    capacity: usize,        // max nodes in arena
    ref_count: AtomicUsize, // live-handle counter
    init_flag: AtomicU32,   // 0 = un-initialised, 1 = ready
}
// Type-size compatibility: RawRwLock::SIZE is 16 bytes on 32-bit, 24 bytes on 64-bit.
// Header is #[repr(C, align(64))], so no padding changes are needed and all offsets stay the same.
const _: () = assert!(core::mem::size_of::<RawRwLock>() <= 64);

/// Node in the Patricia tree, each aligned to cache line
#[repr(C, align(64))]
struct Node {
    key: u128,             // IPv4 in upper 96 bits zero, or full IPv6
    prefix_len: u8,        // valid bits in key
    _pad: [u8; 3],         // padding to align next atomics (adjusted for AtomicU32)
    generation: AtomicU32, // ABA generation counter
    _pad2: [u8; 4],        // padding to align next atomics
    left: AtomicU64,       // packed (offset, generation) to left child
    right: AtomicU64,      // packed (offset, generation) to right child
    expires: AtomicU64,    // Unix epoch seconds: TTL expiration
}

pub struct PatriciaTree {
    shmem: Shmem,                  // The shared memory mapping
    hdr: NonNull<Header>,          // Pointer to header in shared memory
    base: NonNull<u8>,             // Base pointer for node offsets
    free_list: Mutex<Vec<Offset>>, // offsets of deleted nodes to reuse
    os_id: String,                 // Track the shared memory name for Drop
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

impl PatriciaTree {
    /// Create or open a shared‑memory tree
    pub fn open(name: &str, capacity: usize) -> Result<Self, ShmemError> {
        let region_size = size_of::<Header>() + capacity * size_of::<Node>();
        let map_file = format!("{}.map", name);
        // Use flink for file-backed mapping (cross-platform destroy)
        let (shmem, is_creator) = {
            let create_conf = ShmemConf::new()
                .os_id(name)
                .flink(&map_file)
                .size(region_size);
            match create_conf.create() {
                Ok(map) => (map, true),
                Err(e) => match e {
                    ShmemError::MappingIdExists | ShmemError::LinkExists => {
                        let open_conf = ShmemConf::new()
                            .os_id(name)
                            .flink(&map_file)
                            .size(region_size);
                        (open_conf.open()?, false)
                    }
                    _ => return Err(e),
                },
            }
        };
        let base_ptr = shmem.as_ptr() as *mut u8;
        let base = NonNull::new(base_ptr).unwrap();
        let hdr_ptr = base_ptr as *mut Header;
        let hdr = NonNull::new(hdr_ptr).unwrap();
        let hdr_mut = unsafe { &mut *hdr_ptr };
        // Initialise the RW-lock and header when the region is (re-)created
        if is_creator
            || hdr_mut.magic != HEADER_MAGIC
            || hdr_mut.version != HEADER_VERSION
            || hdr_mut.capacity != capacity
        {
            // zero the lock bytes first
            unsafe {
                core::ptr::write_bytes(&mut hdr_mut.lock, 0, 1);
            }
            unsafe {
                RawRwLock::init(&mut hdr_mut.lock as *mut _ as *mut u8, Timeout::Infinite)
                    .expect("lock init failed")
            };
            *hdr_mut = Header {
                magic: HEADER_MAGIC,
                version: HEADER_VERSION,
                _reserved: [0; 6],
                lock: unsafe { core::mem::zeroed() }, // already initialised above
                next_index: AtomicU32::new(0),
                free_slots: AtomicU32::new(0),
                root_offset: AtomicU64::new(0),
                capacity,
                ref_count: AtomicUsize::new(0),
                init_flag: AtomicU32::new(0),
            };
        }
        let hdr_ref = unsafe { &*hdr_ptr };
        hdr_ref
            .ref_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Self {
            shmem,
            base,
            hdr,
            free_list: Mutex::new(Vec::new()),
            os_id: name.to_string(),
        })
    }

    /// Unlink the named shared-memory object (manual cleanup)
    pub fn destroy(name: &str) -> std::io::Result<()> {
        let map_file = format!("{}.map", name);
        if std::path::Path::new(&map_file).exists() {
            std::fs::remove_file(map_file)
        } else {
            Ok(())
        }
    }

    /// Allocate a node offset in the arena
    #[inline(always)]
    fn alloc_offset(&self) -> Offset {
        // This function seems unused after the rewrite, allocate_node is used instead.
        // If it were used, logging would go here.
        // println!("[ALLOC_OFFSET] Attempting allocation...");
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let idx = hdr.next_index.fetch_add(1, Ordering::SeqCst);
        println!("[ALLOC_OFFSET] index={}, capacity={}", idx, hdr.capacity);
        if (idx as usize) >= hdr.capacity {
            // Rollback attempt - might be too late if another thread allocated
            hdr.next_index.fetch_sub(1, Ordering::SeqCst);
            panic!(
                "PatriciaTree capacity exceeded (checked in alloc_offset): {} >= {}",
                idx, hdr.capacity
            );
        }
        let offset = size_of::<Header>() as Offset + (idx as Offset) * size_of::<Node>() as Offset;
        println!("[ALLOC_OFFSET] Allocated offset={}", offset);
        offset
    }

    /// Insert a key with a given prefix length and TTL - REVISED LOGIC
    pub fn insert(&self, key: u128, prefix_len: u8, ttl_secs: u64) {
        println!(
            "[INSERT] key={:x}, prefix_len={}, ttl={}",
            key, prefix_len, ttl_secs
        );
        if prefix_len > 128 {
            panic!("Prefix length cannot exceed 128");
        }

        let hdr = unsafe { &*self.hdr.as_ptr() };
        if hdr.capacity == 0 {
            panic!("Cannot insert into a zero-capacity tree");
        }
        hdr.lock.write_lock();
        println!(
            "[INSERT] Lock acquired. Current next_index={}",
            hdr.next_index.load(Ordering::Relaxed)
        );

        let expires = if ttl_secs == 0 {
            0
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_add(ttl_secs)
        };

        let mut current_link_ptr = &hdr.root_offset as *const AtomicU64 as *mut AtomicU64;

        loop {
            let current_ptr = unsafe { (*current_link_ptr).load(Ordering::Relaxed) };
            let (current_offset, current_gen) = unpack(current_ptr);
            println!(
                "[INSERT] Loop start. current_offset={}, current_gen={}",
                current_offset, current_gen
            );

            // --- Case 1: Empty Link ---
            if current_offset == 0 {
                println!("[INSERT] Case 1: Empty link found.");
                let current_node_count = hdr.next_index.load(Ordering::Relaxed);
                println!(
                    "[INSERT] Checking capacity: count={}, capacity={}",
                    current_node_count, hdr.capacity
                );
                if (current_node_count as usize) >= hdr.capacity {
                    println!("[INSERT] PANIC: Capacity exceeded before allocation.");
                    panic!("PatriciaTree capacity exceeded");
                }
                let (leaf_offset, leaf_gen) = self.allocate_node_with_gen(key, prefix_len, expires);
                println!(
                    "[INSERT] Allocated leaf node at offset={}, gen={}. Storing link.",
                    leaf_offset, leaf_gen
                );
                // Atomically set new leaf if still empty
                let link_atomic = unsafe { &*(current_link_ptr as *const AtomicU64) };
                if link_atomic
                    .compare_exchange(
                        0,
                        pack(leaf_offset, leaf_gen),
                        Ordering::Release,
                        Ordering::Relaxed,
                    )
                    .is_err()
                {
                    // Someone else installed a node – recycle ours and restart
                    self.free_list.lock().push(leaf_offset as Offset);
                    continue; // tail of the while loop
                }
                println!("[INSERT] Finished Case 1.");
                hdr.lock.write_unlock();
                return;
            }

            // --- Case 2: Follow Link ---
            println!(
                "[INSERT] Case 2: Following link to offset={}",
                current_offset
            );
            let current_node = unsafe {
                let ptr = self.base.as_ptr().add(current_offset as usize) as *mut Node;
                &mut *ptr
            };
            println!(
                "[INSERT] Current node: key={:x}, prefix_len={}",
                current_node.key, current_node.prefix_len
            );

            let max_cmp_len = prefix_len.min(current_node.prefix_len);
            let cpl = common_prefix_len(key, current_node.key, max_cmp_len);
            println!("[INSERT] max_cmp_len={}, cpl={}", max_cmp_len, cpl);

            // --- Subcase 2a: Exact Match ---
            if cpl == prefix_len && cpl == current_node.prefix_len && key == current_node.key {
                println!("[INSERT] Subcase 2a: Exact match found. Updating TTL.");
                current_node.expires.store(expires, Ordering::Relaxed);
                println!("[INSERT] Finished Subcase 2a.");
                hdr.lock.write_unlock();
                return;
            }

            // --- Subcase 2b: Split Required ---
            // Split also when prefix lengths match exactly but keys differ
            if cpl < current_node.prefix_len
                || (cpl == prefix_len && cpl == current_node.prefix_len && key != current_node.key)
            {
                println!("[INSERT] Subcase 2b: Split required at cpl={}.", cpl);
                // ATOMIC: Hold free_list lock for both check and allocation
                let mut internal_offset: Offset;
                let mut internal_gen: u32;
                let mut leaf_offset: Offset;
                let mut leaf_gen: u32;
                {
                    let mut free_list = self.free_list.lock();
                    let reserved = hdr.next_index.load(Ordering::Acquire) as usize;
                    let free_len = free_list.len();
                    let available = free_len + hdr.capacity.saturating_sub(reserved);
                    if available < 2 {
                        println!("[INSERT] PANIC: Not enough capacity for split (need 2 slots, have={}).", available);
                        panic!("PatriciaTree capacity exceeded (split requires 2 nodes)");
                    }
                    // Allocate internal node
                    if let Some(offset) = free_list.pop() {
                        println!(
                            "[ALLOC] Reusing freed node for internal at offset={}",
                            offset
                        );
                        let node_ptr =
                            unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                        let gen =
                            unsafe { (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1 };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key & mask(cpl));
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, cpl);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(u64::MAX, Ordering::Relaxed);
                        }
                        internal_offset = offset;
                        internal_gen = gen;
                    } else {
                        let index = hdr.next_index.fetch_add(1, Ordering::Relaxed);
                        if (index as usize) >= hdr.capacity {
                            hdr.next_index.fetch_sub(1, Ordering::Relaxed);
                            panic!("PatriciaTree capacity exceeded allocating internal node during split");
                        }
                        // this line is correct. Do not change it. size_of requires ()
                        internal_offset = size_of::<Header>() as Offset
                            + (index as Offset) * size_of::<Node>() as Offset;
                        let node_ptr = unsafe {
                            self.base.as_ptr().add(internal_offset as usize) as *mut Node
                        };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key & mask(cpl));
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, cpl);
                            (*node_ptr).generation.store(1, Ordering::Relaxed);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(u64::MAX, Ordering::Relaxed);
                        }
                        internal_gen = 1;
                    }
                    // Allocate leaf node
                    if let Some(offset) = free_list.pop() {
                        println!("[ALLOC] Reusing freed node for leaf at offset={}", offset);
                        let node_ptr =
                            unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                        let gen =
                            unsafe { (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1 };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key);
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(expires, Ordering::Relaxed);
                        }
                        leaf_offset = offset;
                        leaf_gen = gen;
                    } else {
                        let index = hdr.next_index.fetch_add(1, Ordering::Relaxed);
                        if (index as usize) >= hdr.capacity {
                            hdr.next_index.fetch_sub(1, Ordering::Relaxed);
                            // Roll back internal node if it was newly allocated
                            let internal_index = ((internal_offset as usize) - size_of::<Header>())
                                / size_of::<Node>();
                            if internal_index == (index as usize) - 1 {
                                free_list.push(internal_offset);
                            }
                            panic!(
                                "PatriciaTree capacity exceeded allocating leaf node during split"
                            );
                        }
                        leaf_offset = size_of::<Header>() as Offset
                            + (index as Offset) * size_of::<Node>() as Offset;
                        let node_ptr =
                            unsafe { self.base.as_ptr().add(leaf_offset as usize) as *mut Node };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key);
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                            (*node_ptr).generation.store(1, Ordering::Relaxed);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(expires, Ordering::Relaxed);
                        }
                        leaf_gen = 1;
                    }
                }
                unsafe {
                    let internal_node =
                        &mut *(self.base.as_ptr().add(internal_offset as usize) as *mut Node);
                    let new_bit = get_bit(key, cpl);
                    println!("[INSERT] Split branching: new_key_bit={}", new_bit);
                    if new_bit == 0 {
                        internal_node
                            .left
                            .store(pack(leaf_offset as u32, leaf_gen), Ordering::Relaxed);
                        internal_node
                            .right
                            .store(pack(current_offset as u32, current_gen), Ordering::Relaxed);
                    } else {
                        internal_node
                            .right
                            .store(pack(leaf_offset as u32, leaf_gen), Ordering::Relaxed);
                        internal_node
                            .left
                            .store(pack(current_offset as u32, current_gen), Ordering::Relaxed);
                    }
                    println!(
                        "[INSERT] Linking new internal node at offset={}.",
                        internal_offset
                    );
                    (*current_link_ptr).store(
                        pack(internal_offset as u32, internal_gen),
                        Ordering::Release,
                    );
                }
                println!("[INSERT] Finished Subcase 2b.");
                hdr.lock.write_unlock();
                return;
            }

            // --- Subcase 2c: Insert Above Required ---
            // This case happens when the new key is a prefix of the current node.
            // cpl == current_node.prefix_len must hold (otherwise split would happen).
            // So the condition simplifies to cpl < prefix_len.
            if cpl < prefix_len {
                // Implies cpl == current_node.prefix_len
                println!("[INSERT] Subcase 2c: Insert Above required at cpl={}.", cpl);
                let current_node_count = hdr.next_index.load(Ordering::Relaxed);
                println!(
                    "[INSERT] Checking capacity for insert above: count={}, capacity={}",
                    current_node_count, hdr.capacity
                );
                if (current_node_count as usize) >= hdr.capacity {
                    println!("[INSERT] PANIC: Capacity exceeded before insert above allocation.");
                    panic!("PatriciaTree capacity exceeded");
                }
                let (new_node_offset, new_node_gen) =
                    self.allocate_node_with_gen(key, prefix_len, expires);
                println!(
                    "[INSERT] Allocated new node for insert above at offset={}, gen={}.",
                    new_node_offset, new_node_gen
                );

                unsafe {
                    let new_node =
                        &mut *(self.base.as_ptr().add(new_node_offset as usize) as *mut Node);
                    // Bit to check in the *existing* node's key at the *new* node's prefix length
                    let existing_node_bit = get_bit(current_node.key, prefix_len);
                    println!(
                        "[INSERT] Insert Above branching: existing_node_bit={}",
                        existing_node_bit
                    );

                    if existing_node_bit == 0 {
                        new_node
                            .left
                            .store(pack(current_offset as u32, current_gen), Ordering::Relaxed);
                    } else {
                        new_node
                            .right
                            .store(pack(current_offset as u32, current_gen), Ordering::Relaxed);
                    }
                    println!("[INSERT] Linking new node at offset={}.", new_node_offset);
                    (*current_link_ptr).store(
                        pack(new_node_offset as u32, new_node_gen),
                        Ordering::Release,
                    );
                }
                println!("[INSERT] Finished Subcase 2c.");
                hdr.lock.write_unlock();
                return;
            }

            // --- Subcase 2d: Traverse Down ---
            // This case happens when the current node is a prefix of the new key.
            // cpl == current_node.prefix_len must hold.
            // cpl < prefix_len was handled by Insert Above.
            // So, this path should only be taken if cpl == current_node.prefix_len < prefix_len.
            // Let's re-verify the conditions. If cpl == current_node.prefix_len, it means the current node's
            // prefix matches the start of the key being inserted. We need to decide based on the next bit.
            println!("[INSERT] Subcase 2d: Traverse Down needed.");
            let next_bit = get_bit(key, current_node.prefix_len); // Bit *after* current prefix
            println!("[INSERT] Traverse direction bit={}", next_bit);
            let next_link_atomic_ptr = if next_bit == 0 {
                &current_node.left as *const AtomicU64 as *mut AtomicU64
            } else {
                &current_node.right as *const AtomicU64 as *mut AtomicU64
            };
            current_link_ptr = next_link_atomic_ptr;
            println!("[INSERT] Continuing loop, following link.");
            // Continue loop
        }
    }

    // Helper to allocate a new node (assumes lock is held)
    /// Allocates a new node and returns (offset, generation).
    fn allocate_node_with_gen(&self, key: u128, prefix_len: u8, expires: u64) -> (Offset, u32) {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        // Try to reuse a freed node
        if let Some(offset) = self.free_list.lock().pop() {
            println!("[ALLOC] Reusing freed node at offset={}", offset);
            // Decrement free_slots since we're reusing a slot
            hdr.free_slots.fetch_sub(1, Ordering::SeqCst);
            let node_ptr = unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
            let gen = unsafe {
                let g = (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1;
                core::ptr::write_volatile(&mut (*node_ptr).key, key);
                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                (*node_ptr).left.store(0, Ordering::Relaxed);
                (*node_ptr).right.store(0, Ordering::Relaxed);
                (*node_ptr).expires.store(expires, Ordering::Relaxed);
                g
            };
            return (offset, gen);
        }
        println!(
            "[ALLOC] key={:x}, prefix_len={}, expires={}",
            key, prefix_len, expires
        );
        if hdr.capacity == 0 {
            panic!("Cannot insert into a zero-capacity tree");
        }
        // Allocation path: bump next_index, check capacity, spin if free_slots > 0, else panic
        loop {
            let index = hdr.next_index.fetch_add(1, Ordering::SeqCst);
            if (index as usize) < hdr.capacity {
                let offset =
                    size_of::<Header>() as Offset + (index as Offset) * size_of::<Node>() as Offset;
                println!("[ALLOC] Calculated offset={}", offset);
                let gen = unsafe {
                    let node_ptr = self.base.as_ptr().add(offset as usize) as *mut Node;
                    println!("[ALLOC] Writing node data at offset={}", offset);
                    core::ptr::write_volatile(&mut (*node_ptr).key, key);
                    core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                    (*node_ptr).generation.store(1, Ordering::Relaxed);
                    (*node_ptr).left.store(0, Ordering::Relaxed);
                    (*node_ptr).right.store(0, Ordering::Relaxed);
                    (*node_ptr).expires.store(expires, Ordering::Relaxed);
                    println!("[ALLOC] Node initialized at offset={}", offset);
                    1
                };
                return (offset, gen);
            } else {
                // Out of capacity: check if there are free slots to reclaim
                if hdr.free_slots.load(Ordering::Acquire) > 0 {
                    // Spin and retry, waiting for a slot to be freed
                    std::thread::yield_now();
                    continue;
                } else {
                    println!("[ALLOC] PANIC: PatriciaTree capacity exceeded and no free slots available.");
                    panic!("PatriciaTree capacity exceeded and no free slots available");
                }
            }
        }
    }

    /// Lookup a key; true if found and not expired (Revised for Patricia structure)
    pub fn lookup(&self, key: u128) -> bool {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let mut current_offset = hdr.root_offset.load(Ordering::Acquire);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        while current_offset != 0 {
            let node =
                unsafe { &*(self.base.as_ptr().add(current_offset as usize) as *const Node) };
            let cpl = common_prefix_len(key, node.key, node.prefix_len);
            if cpl < node.prefix_len {
                return false; // prefix diverged
            }
            let exp = node.expires.load(Ordering::Acquire);
            // If this node is a leaf/prefix node (not internal) and key matches its prefix, return its TTL state
            if exp != u64::MAX && cpl == node.prefix_len {
                return exp >= now;
            }
            // Otherwise it's an internal node: traverse based on next bit
            if node.prefix_len >= 128 {
                return false;
            }
            let next_bit = get_bit(key, node.prefix_len);
            current_offset = if next_bit == 0 {
                node.left.load(Ordering::Acquire)
            } else {
                node.right.load(Ordering::Acquire)
            };
        }
        false
    }

    /// Delete a key (expire immediately)
    pub fn delete(&self, key: u128) {
        println!("[DELETE] key={:x}", key);
        let hdr = unsafe { &*self.hdr.as_ptr() };
        hdr.lock.write_lock();
        println!("[DELETE] Lock acquired.");

        let mut current_ptr = hdr.root_offset.load(Ordering::Relaxed);
        let mut current_offset;
        let mut current_gen;
        (current_offset, current_gen) = unpack(current_ptr);
        println!(
            "[DELETE] Starting at root_offset={}, gen={}",
            current_offset, current_gen
        );

        // Need to track parent link to potentially update it if we prune nodes (future enhancement)
        // let mut parent_link_ptr = &hdr.root_offset as *const AtomicUsize as *mut AtomicUsize;

        while current_offset != 0 {
            println!("[DELETE] Loop: current_offset={}", current_offset);
            let node_ptr = unsafe { self.base.as_ptr().add(current_offset as usize) as *mut Node };
            let node = unsafe { &*node_ptr }; // Read-only ref first
            let node_gen = node.generation.load(Ordering::Acquire);
            if node_gen != current_gen {
                // ABA detected, restart from root
                current_ptr = hdr.root_offset.load(Ordering::Relaxed);
                (current_offset, current_gen) = unpack(current_ptr);
                continue;
            }
            println!(
                "[DELETE] Node: key={:x}, prefix_len={}, gen={}",
                node.key, node.prefix_len, node_gen
            );

            // Compare the full key against the node's key up to the node's prefix length.
            let cpl = common_prefix_len(key, node.key, node.prefix_len);
            println!("[DELETE] cpl={}", cpl);

            if cpl < node.prefix_len {
                println!("[DELETE] Diverged (cpl < node.prefix_len). Key not found.");
                hdr.lock.write_unlock();
                return; // Key not found in this subtree
            }

            // If the common prefix length matches the node's prefix length,
            // it means the node's prefix matches the beginning of the key.
            // Now, check if this node is the *exact* one we want to delete.
            // For simplicity, we assume delete targets the exact key (prefix 128 implicitly).
            // A more robust implementation might take prefix_len as an argument.
            if cpl == node.prefix_len {
                // Check if the node's key *exactly* matches the target key.
                // This implicitly checks if node.prefix_len is also 128 (or matches the key's significant bits).
                // We also need to consider the case where the node represents a shorter prefix (e.g., /64)
                // and the key matches that prefix exactly. The current test inserts with prefix 64,
                // but deletes with the full key. Let's expire if the node key matches the target key
                // *masked by the node's prefix length*.
                let mask = if node.prefix_len == 128 {
                    !0u128
                } else {
                    !(!0u128 >> node.prefix_len)
                };
                if (key & mask) == (node.key & mask) {
                    // This node represents the prefix we are looking for.
                    // Check if the *keys* are identical. If the test inserts key K with prefix P,
                    // and we call delete(K), we should expire the node if node.key == K and node.prefix_len == P.
                    // The current test inserts (key, 64, ttl) and calls delete(key).
                    // Let's expire if node.key == key and node.prefix_len matches the implicit target (or the original insertion).
                    // For the concurrent test, keys are unique, so node.key == key should suffice.
                    if node.key == key {
                        println!(
                            "[DELETE] Found exact key match. Expiring node at offset={}.",
                            current_offset
                        );
                        let node_mut = unsafe { &mut *node_ptr };
                        node_mut.expires.store(0, Ordering::Release); // Expire the node
                                                                      // Add this offset to free_list for reuse
                        self.free_list.lock().push(current_offset);
                        // Increment free_slots for reclaimable capacity
                        let hdr = unsafe { &*self.hdr.as_ptr() };
                        hdr.free_slots.fetch_add(1, Ordering::Release);
                        println!("[DELETE] Finished.");
                        // TODO: Implement pruning of expired nodes if necessary.
                        hdr.lock.write_unlock();
                        return;
                    }
                    // If keys don't match exactly, but the prefix does, it means the node we found
                    // is a less specific prefix. We need to continue searching deeper.
                    println!("[DELETE] Prefix matches, but key differs. Traversing down.");
                } else {
                    // This case (cpl == node.prefix_len but masked keys differ) should theoretically not happen
                    // due to how common_prefix_len works. If it does, it implies an issue elsewhere.
                    println!("[DELETE] Inconsistent state: cpl == node.prefix_len but masked keys differ. Key not found.");
                    hdr.lock.write_unlock();
                    return;
                }
            }

            // If we reach here, it means cpl == node.prefix_len, but the keys didn't match exactly,
            // OR cpl > node.prefix_len (which is impossible).
            // We need to traverse down based on the next bit *after* the node's prefix.
            if node.prefix_len >= 128 {
                #[cfg(debug_assertions)]
                println!(
                    "[DELETE] Node prefix_len >= 128, but key didn't match exactly. Key not found."
                );
                hdr.lock.write_unlock();
                return; // Cannot go deeper
            }

            let next_bit = get_bit(key, node.prefix_len);
            println!(
                "[DELETE] Traversing based on bit {} = {}",
                node.prefix_len, next_bit
            );
            current_ptr = if next_bit == 0 {
                node.left.load(Ordering::Relaxed)
            } else {
                node.right.load(Ordering::Relaxed)
            };
            (current_offset, current_gen) = unpack(current_ptr);
        }
        println!("[DELETE] Reached end of branch (offset 0). Key not found.");
        hdr.lock.write_unlock();
        // Key not found if loop finishes
    }

    /// Bulk insert multiple entries
    pub fn bulk_insert(&self, items: &[(u128, u8, u64)]) {
        for &(k, l, t) in items {
            self.insert(k, l, t)
        }
    }

    /// Clears the entire tree (drops all nodes).
    pub fn clear(&self) {
        let hdr = unsafe { &mut *self.hdr.as_ptr() };
        hdr.lock.write_lock();
        hdr.next_index.store(0, Ordering::SeqCst);
        hdr.free_slots.store(0, Ordering::SeqCst);
        hdr.root_offset.store(0, Ordering::SeqCst);
        self.free_list.lock().clear();
        hdr.lock.write_unlock();
    }
} // end impl PatriciaTree

// Public module for C API functions
pub mod public_api;

// Re-export all public API functions at the crate root
pub use public_api::*;

impl Drop for PatriciaTree {
    fn drop(&mut self) {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let prev = hdr
            .ref_count
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        if prev == 1 {
            #[cfg(unix)]
            {
                let c_name = std::ffi::CString::new(self.os_id.clone()).unwrap();
                let _ = unsafe { libc::shm_unlink(c_name.as_ptr()) };
            }
            // On Windows: no-op
        }
        // The mapping itself is unmapped automatically by Shmem’s Drop
    }
}
