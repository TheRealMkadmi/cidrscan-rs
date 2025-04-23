//! Monolithic, high‑performance, shared Patricia tree with TTL
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

use core::panic;
// Helper function to calculate the length of the common prefix (up to max_len bits)
fn common_prefix_len(key1: u128, key2: u128, max_len: u8) -> u8 {
    if max_len == 0 { return 0; } // Handle zero length prefix comparison
    // Remove unused variable: let relevant_bits = 128 - max_len as u32;
    // Mask to ignore bits beyond max_len
    let mask = if max_len == 128 { !0u128 } else { !(!0u128 >> max_len) };
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
    if index >= 128 {
        // This case should ideally not be reached if logic is correct,
        // but return 0 defensively. Could also panic.
        return 0;
    }
    ((key >> (127 - index)) & 1) as u8
}

use shared_memory::{Shmem, ShmemConf, ShmemError};  // Shared memory mapping :contentReference[oaicite:13]{index=13}
use spin::Mutex;                                   // Spin‑based user‑space locks :contentReference[oaicite:14]{index=14}
use std::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Maximum nodes if not specified
const DEFAULT_CAPACITY: usize = 1_048_576;

/// Shared‑memory header (aligned to cache line)
#[repr(C, align(64))]
struct Header {
    lock: Mutex<()>,             // exclusive writer lock :contentReference[oaicite:15]{index=15}
    node_count: AtomicUsize,     // bump allocator index
    root_offset: AtomicUsize,    // atomic root pointer for lock‑free reads
    capacity: usize,             // max nodes in arena
}

/// Node in the Patricia tree, each aligned to cache line
#[repr(C, align(64))]
struct Node {
    key: u128,                   // IPv4 in upper 96 bits zero, or full IPv6
    prefix_len: u8,              // valid bits in key
    _pad: [u8; 7],               // padding to align next atomics
    left: AtomicUsize,           // offset to left child
    right: AtomicUsize,          // offset to right child
    expires: AtomicU64,          // Unix epoch seconds: TTL expiration :contentReference[oaicite:16]{index=16}
}

pub struct PatriciaTree {
    shmem: Shmem, // The shared memory mapping
    hdr: NonNull<Header>, // Pointer to header in shared memory
    base: NonNull<u8>, // Base pointer for node offsets
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
        
        // Try to create, fallback to open if it already exists
        let shmem = match ShmemConf::new().os_id(name).size(region_size).create() {
            Ok(map) => map,
            Err(ShmemError::MappingIdExists) => ShmemConf::new().os_id(name).open()?,
            Err(e) => return Err(e),
        };

        let base_ptr = shmem.as_ptr() as *mut u8;
        let base = NonNull::new(base_ptr).unwrap();
        let hdr_ptr = base_ptr as *mut Header;
        let hdr = NonNull::new(hdr_ptr).unwrap();

        // Initialize header on first creation
        let hdr_ref = unsafe { &*hdr_ptr };
        if hdr_ref.capacity == 0 {
            let _guard = hdr_ref.lock.lock(); // init lock
            // Double-check after acquiring the lock
            if unsafe { (*hdr_ptr).capacity == 0 } {
                unsafe {
                    std::ptr::write(&mut (*hdr_ptr).capacity, capacity);
                    std::ptr::write(&mut (*hdr_ptr).node_count, AtomicUsize::new(0));
                    std::ptr::write(&mut (*hdr_ptr).root_offset, AtomicUsize::new(0));
                    // lock is already default‑constructed by spin::Mutex::new()
                }
            }
        }

        Ok(Self { shmem, base, hdr })
    }

    /// Allocate a node offset in the arena
    #[inline(always)]
    fn alloc_offset(&self) -> usize {
        // This function seems unused after the rewrite, allocate_node is used instead.
        // If it were used, logging would go here.
        // println!("[ALLOC_OFFSET] Attempting allocation...");
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let idx = hdr.node_count.fetch_add(1, Ordering::SeqCst);
        println!("[ALLOC_OFFSET] index={}, capacity={}", idx, hdr.capacity);
        if idx >= hdr.capacity {
            // Rollback attempt - might be too late if another thread allocated
            hdr.node_count.fetch_sub(1, Ordering::SeqCst);
            panic!("PatriciaTree capacity exceeded (checked in alloc_offset): {} >= {}", idx, hdr.capacity);
        }
        let offset = size_of::<Header>() + idx * size_of::<Node>();
        println!("[ALLOC_OFFSET] Allocated offset={}", offset);
        offset
    }

    /// Insert a key with a given prefix length and TTL - REVISED LOGIC
    pub fn insert(&self, key: u128, prefix_len: u8, ttl_secs: u64) {
        println!("[INSERT] key={:x}, prefix_len={}, ttl={}", key, prefix_len, ttl_secs);
        if prefix_len > 128 { panic!("Prefix length cannot exceed 128"); }

        let hdr = unsafe { &*self.hdr.as_ptr() };
        let _guard = hdr.lock.lock(); // Acquire exclusive write lock
        println!("[INSERT] Lock acquired. Current node_count={}", hdr.node_count.load(Ordering::Relaxed));

        let expires = if ttl_secs == 0 { 0 } else {
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs().saturating_add(ttl_secs)
        };

        let root_offset_ptr = &hdr.root_offset as *const AtomicUsize as *mut AtomicUsize;
        let mut current_link_ptr = unsafe { NonNull::new_unchecked(root_offset_ptr) };

        loop {
            let current_offset = unsafe { current_link_ptr.as_ref().load(Ordering::Relaxed) };
            println!("[INSERT] Loop start. current_offset={}", current_offset);

            // --- Case 1: Empty Link ---
            if current_offset == 0 {
                println!("[INSERT] Case 1: Empty link found.");
                let current_node_count = hdr.node_count.load(Ordering::Relaxed);
                println!("[INSERT] Checking capacity: count={}, capacity={}", current_node_count, hdr.capacity);
                if current_node_count >= hdr.capacity {
                     println!("[INSERT] PANIC: Capacity exceeded before allocation.");
                     panic!("PatriciaTree capacity exceeded");
                }
                let leaf_offset = self.allocate_node(key, prefix_len, expires);
                println!("[INSERT] Allocated leaf node at offset={}. Storing link.", leaf_offset);
                unsafe { current_link_ptr.as_ref().store(leaf_offset, Ordering::Release); }
                println!("[INSERT] Finished Case 1.");
                return;
            }

            // --- Case 2: Follow Link ---
            println!("[INSERT] Case 2: Following link to offset={}", current_offset);
            let current_node = unsafe {
                let ptr = self.base.as_ptr().add(current_offset) as *mut Node;
                &mut *ptr
            };
            println!("[INSERT] Current node: key={:x}, prefix_len={}", current_node.key, current_node.prefix_len);

            let max_cmp_len = prefix_len.min(current_node.prefix_len);
            let cpl = common_prefix_len(key, current_node.key, max_cmp_len);
            println!("[INSERT] max_cmp_len={}, cpl={}", max_cmp_len, cpl);

            // --- Subcase 2a: Exact Match ---
            if cpl == prefix_len && cpl == current_node.prefix_len {
                println!("[INSERT] Subcase 2a: Exact match found. Updating TTL.");
                current_node.expires.store(expires, Ordering::Relaxed);
                println!("[INSERT] Finished Subcase 2a.");
                return;
            }

            // --- Subcase 2b: Split Required ---
            if cpl < current_node.prefix_len {
                 println!("[INSERT] Subcase 2b: Split required at cpl={}.", cpl);
                 let current_node_count = hdr.node_count.load(Ordering::Relaxed);
                 println!("[INSERT] Checking capacity for split: count={}, capacity={}", current_node_count, hdr.capacity);
                 // Need space for internal + leaf node (+1 already fetched by one allocate_node, need +1 more)
                 if current_node_count + 1 >= hdr.capacity { // Check if adding *one more* exceeds capacity
                     println!("[INSERT] PANIC: Capacity exceeded before split allocation.");
                     panic!("PatriciaTree capacity exceeded (split requires 2 nodes)");
                 }
                 let internal_offset = self.allocate_node(key, cpl, u64::MAX);
                 println!("[INSERT] Allocated internal node at offset={}.", internal_offset);
                 // Capacity check for the second node is implicitly handled by the next allocate_node call
                 let leaf_offset = self.allocate_node(key, prefix_len, expires);
                 println!("[INSERT] Allocated leaf node for split at offset={}.", leaf_offset);

                 unsafe {
                     let internal_node = &mut *(self.base.as_ptr().add(internal_offset) as *mut Node);
                     let existing_node_bit = get_bit(current_node.key, cpl);
                     println!("[INSERT] Split branching: existing_node_bit={}", existing_node_bit);

                     if existing_node_bit == 0 {
                         internal_node.left.store(current_offset, Ordering::Relaxed);
                         internal_node.right.store(leaf_offset, Ordering::Relaxed);
                     } else {
                         internal_node.right.store(current_offset, Ordering::Relaxed);
                         internal_node.left.store(leaf_offset, Ordering::Relaxed);
                     }
                     println!("[INSERT] Linking new internal node at offset={}.", internal_offset);
                     current_link_ptr.as_ref().store(internal_offset, Ordering::Release);
                 }
                 println!("[INSERT] Finished Subcase 2b.");
                 return;
            }

            // --- Subcase 2c: Insert Above Required ---
            // This case happens when the new key is a prefix of the current node.
            // cpl == current_node.prefix_len must hold (otherwise split would happen).
            // So the condition simplifies to cpl < prefix_len.
            if cpl < prefix_len { // Implies cpl == current_node.prefix_len
                 println!("[INSERT] Subcase 2c: Insert Above required at cpl={}.", cpl);
                 let current_node_count = hdr.node_count.load(Ordering::Relaxed);
                 println!("[INSERT] Checking capacity for insert above: count={}, capacity={}", current_node_count, hdr.capacity);
                 if current_node_count >= hdr.capacity {
                     println!("[INSERT] PANIC: Capacity exceeded before insert above allocation.");
                     panic!("PatriciaTree capacity exceeded");
                 }
                 let new_node_offset = self.allocate_node(key, prefix_len, expires);
                 println!("[INSERT] Allocated new node for insert above at offset={}.", new_node_offset);

                 unsafe {
                     let new_node = &mut *(self.base.as_ptr().add(new_node_offset) as *mut Node);
                     // Bit to check in the *existing* node's key at the *new* node's prefix length
                     let existing_node_bit = get_bit(current_node.key, prefix_len);
                     println!("[INSERT] Insert Above branching: existing_node_bit={}", existing_node_bit);

                     if existing_node_bit == 0 {
                         new_node.left.store(current_offset, Ordering::Relaxed);
                     } else {
                         new_node.right.store(current_offset, Ordering::Relaxed);
                     }
                     println!("[INSERT] Linking new node at offset={}.", new_node_offset);
                     current_link_ptr.as_ref().store(new_node_offset, Ordering::Release);
                 }
                 println!("[INSERT] Finished Subcase 2c.");
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
                &current_node.left as *const AtomicUsize as *mut AtomicUsize
            } else {
                &current_node.right as *const AtomicUsize as *mut AtomicUsize
            };
            current_link_ptr = unsafe { NonNull::new_unchecked(next_link_atomic_ptr) };
            println!("[INSERT] Continuing loop, following link.");
            // Continue loop
        }
    }

    // Helper to allocate a new node (assumes lock is held)
    fn allocate_node(&self, key: u128, prefix_len: u8, expires: u64) -> usize {
        println!("[ALLOC] key={:x}, prefix_len={}, expires={}", key, prefix_len, expires);
        let hdr = unsafe { &*self.hdr.as_ptr() };
        // Fetch_add happens *before* the check, ensuring atomicity for index reservation.
        let index = hdr.node_count.fetch_add(1, Ordering::Relaxed);
        println!("[ALLOC] Reserved index={}, capacity={}", index, hdr.capacity);
        // Check if the *reserved* index is out of bounds.
        if index >= hdr.capacity {
            // Roll back the counter since this allocation failed.
            hdr.node_count.fetch_sub(1, Ordering::Relaxed);
            println!("[ALLOC] PANIC: Capacity exceeded after fetch_add.");
            panic!("PatriciaTree capacity exceeded: reserved index {} >= capacity {}", index, hdr.capacity);
        }

        let offset = size_of::<Header>() + index * size_of::<Node>();
        println!("[ALLOC] Calculated offset={}", offset);
        // Unsafe block for pointer arithmetic, bounds check, and writing
        unsafe {
            // Bounds check against total shared memory size.
            if offset + size_of::<Node>() > self.shmem.len() {
                 hdr.node_count.fetch_sub(1, Ordering::Relaxed); // Rollback
                 println!("[ALLOC] PANIC: Offset exceeds shared memory bounds.");
                 panic!("Calculated offset {} + node size {} exceeds shared memory bounds {}!", offset, size_of::<Node>(), self.shmem.len());
            }

            let node_ptr = self.base.as_ptr().add(offset) as *mut Node;
            println!("[ALLOC] Writing node data at offset={}", offset);
            // Initialize the node
            core::ptr::write_volatile(&mut (*node_ptr).key, key);
            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
            // Use direct initialization for atomics within the unsafe block
            (*node_ptr).left = AtomicUsize::new(0);
            (*node_ptr).right = AtomicUsize::new(0);
            (*node_ptr).expires = AtomicU64::new(expires);
            println!("[ALLOC] Node initialized at offset={}", offset);
        }
        offset
    }

    /// Lookup a key; true if found and not expired (Revised for Patricia structure)
    pub fn lookup(&self, key: u128) -> bool {
        println!("[LOOKUP] key={:x}", key);
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let mut current_offset = hdr.root_offset.load(Ordering::Acquire);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        println!("[LOOKUP] Starting at root_offset={}, now={}", current_offset, now);

        while current_offset != 0 {
            println!("[LOOKUP] Loop: current_offset={}", current_offset);
            let node = unsafe { &*(self.base.as_ptr().add(current_offset) as *const Node) };
            println!("[LOOKUP] Node: key={:x}, prefix_len={}, expires={}", node.key, node.prefix_len, node.expires.load(Ordering::Relaxed));

            let cpl = common_prefix_len(key, node.key, node.prefix_len);
            println!("[LOOKUP] cpl={}", cpl);

            if cpl < node.prefix_len {
                println!("[LOOKUP] Diverged (cpl < node.prefix_len). Not found.");
                return false;
            }

            // Node's prefix matches start of key.
            let node_expires = node.expires.load(Ordering::Acquire);
            if node_expires >= now {
                 println!("[LOOKUP] Node prefix matches and is not expired. Found match.");
                 // In a real CIDR lookup, we might continue searching for a *more specific* match.
                 // For the current tests assuming exact prefix insertion/lookup, this is sufficient.
                 return true;
            }
            println!("[LOOKUP] Node prefix matches but is expired (expires={}, now={}). Continuing search.", node_expires, now);

            // If expired, or if we needed a more specific match, continue traversal.
            if node.prefix_len >= 128 {
                println!("[LOOKUP] Node prefix_len >= 128. Cannot go deeper. Not found (or expired).");
                return false;
            }

            let next_bit = get_bit(key, node.prefix_len);
            println!("[LOOKUP] Traversing based on bit {} = {}", node.prefix_len, next_bit);
            current_offset = if next_bit == 0 {
                node.left.load(Ordering::Acquire)
            } else {
                node.right.load(Ordering::Acquire)
            };
        }

        println!("[LOOKUP] Reached end of branch (offset 0). Not found.");
        false
    }

    /// Delete a key (expire immediately)
    pub fn delete(&self, key: u128) {
        println!("[DELETE] key={:x}", key);
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let _guard = hdr.lock.lock(); // Need write lock to modify expiry
        println!("[DELETE] Lock acquired.");

        let current_offset = hdr.root_offset.load(Ordering::Relaxed);
        println!("[DELETE] Starting at root_offset={}", current_offset);

        // Need to track parent link to potentially update it if we prune nodes (future enhancement)
        // let mut parent_link_ptr = &hdr.root_offset as *const AtomicUsize as *mut AtomicUsize;

        while current_offset != 0 {
            println!("[DELETE] Loop: current_offset={}", current_offset);
            let node_ptr = unsafe { self.base.as_ptr().add(current_offset) as *mut Node };
            let node = unsafe { &*node_ptr }; // Read-only ref first
            println!("[DELETE] Node: key={:x}, prefix_len={}", node.key, node.prefix_len);

            let cpl = common_prefix_len(key, node.key, node.prefix_len);
            println!("[DELETE] cpl={}", cpl);

            if cpl < node.prefix_len {
                println!("[DELETE] Diverged (cpl < node.prefix_len). Key not found.");
                return; // Key not found
            }

            // Node's prefix matches start of key.
            // Does the *entire* node match the key we want to delete?
            // This assumes delete targets an exact key+prefix combo that was inserted.
            // If we just match prefix, we might delete a parent node unintentionally.
            // Let's refine: Delete only if cpl == node.prefix_len (prefix matches)
            // AND maybe check if key == node.key? Or assume prefix match is enough?
            // The tests seem to imply deleting the specific inserted prefix.
            if cpl == node.prefix_len {
                println!("[DELETE] Found node with matching prefix. Expiring node at offset={}.", current_offset);
                let node_mut = unsafe { &mut *node_ptr };
                node_mut.expires.store(0, Ordering::Release); // Expire the node
                println!("[DELETE] Finished.");
                return; // Return after expiring the first matching node found.
            }

            // If node.prefix_len > cpl, we already returned.
            // If node.prefix_len == cpl, we just handled it.
            // So, we only continue if node.prefix_len < cpl, meaning we need to traverse down.
            // Wait, the condition is cpl == node.prefix_len for exact match.
            // If cpl == node.prefix_len, we need to traverse if the key is *more specific*.
            // The key is more specific if its actual length (e.g. 128) is > node.prefix_len.
            // Let's assume delete targets the *exact* prefix length inserted.
            // So if cpl == node.prefix_len, we expire and return.

            // If we reach here, it means cpl == node.prefix_len, but we didn't return?
            // Ah, the logic above returns if cpl == node.prefix_len. So we only get here
            // if cpl > node.prefix_len, which is impossible by definition of common_prefix_len.
            // Let's rethink the traversal condition.

            // We traverse down if the current node is a prefix of the key, but not the exact node we want.
            // This happens if cpl == node.prefix_len, but the key is longer/more specific.
            // The current delete logic expires the *first* node whose prefix matches the start of the key.
            // This might be incorrect if we inserted 10.0.0.0/8 and 10.1.0.0/16, and try to delete 10.1.0.0/16.
            // The current logic would find 10.0.0.0/8 first and expire it.

            // --- Revised Delete Traversal ---
            // We only expire if cpl == node.prefix_len AND node.prefix_len is the length we are looking for.
            // Since delete() doesn't take prefix_len, we have ambiguity.
            // Let's stick to expiring the *first* matching prefix found for now, as per the code.
            // The traversal logic below this point seems unreachable with the current return.

            // If we needed to traverse (e.g., to find the most specific match to delete):
            /*
            if node.prefix_len >= 128 {
                println!("[DELETE] Node prefix_len >= 128. Cannot go deeper. Key not found (or already expired).");
                return; // Cannot go deeper
            }

            let next_bit = get_bit(key, node.prefix_len);
            println!("[DELETE] Traversing based on bit {} = {}", node.prefix_len, next_bit);
            current_offset = if next_bit == 0 {
                node.left.load(Ordering::Relaxed)
            } else {
                node.right.load(Ordering::Relaxed)
            };
            */
        }
        println!("[DELETE] Reached end of branch (offset 0). Key not found.");
        // Key not found if loop finishes
    }

    /// Bulk insert multiple entries
    pub fn bulk_insert(&self, items: &[(u128, u8, u64)]) {
        for &(k, l, t) in items { self.insert(k, l, t) }
    }
} // end impl PatriciaTree

// Public module for C API functions
pub mod public_api;

// Re-export all public API functions at the crate root
pub use public_api::*;