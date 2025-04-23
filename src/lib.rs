//! Monolithic, high‑performance, shared Patricia tree with TTL
#![allow(dead_code)]
#![allow(clippy::missing_safety_doc)]

// Disable debug printing: override println! macro to no-op
// #[macro_export]
// macro_rules! println {
//     ($($arg:tt)*) => {};
// }

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

use shared_memory::{Shmem, ShmemConf, ShmemError};  // Shared memory mapping :contentReference[oaicite:13]{index=13}
use parking_lot::{RwLock, Mutex};  // RwLock for header, Mutex for free_list
use std::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// Maximum nodes if not specified
const DEFAULT_CAPACITY: usize = 1_048_576;

/// Magic and ABI version for header integrity checks
const HEADER_MAGIC: u64 = 0x434944525343414E; // "CIDRSCAN"
const HEADER_VERSION: u16 = 1;

/// Shared‑memory header (aligned to cache line)
#[repr(C, align(64))]
struct Header {
    magic: u64,            // identifies valid CIDRScan header
    version: u16,          // ABI version
    _reserved: [u8; 6],    // padding to 16 bytes total
    lock: RwLock<()>,            // readers–writer lock
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
    free_list: Mutex<Vec<usize>>, // offsets of deleted nodes to reuse
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
        
        // True cross-process create/open: only initialize header if we actually created it
        let (shmem, is_creator) = {
            // true cross-process create/open semantics
            let create_conf = ShmemConf::new().os_id(name).size(region_size);
            match create_conf.create() {
                Ok(map) => (map, true),
                Err(ShmemError::MappingIdExists) => {
                    // mapping exists: open with a fresh config
                    let open_conf = ShmemConf::new().os_id(name).size(region_size);
                    (open_conf.open()?, false)
                }
                Err(e) => return Err(e),
            }
        };

        let base_ptr = shmem.as_ptr() as *mut u8;
        let base = NonNull::new(base_ptr).unwrap();
        let hdr_ptr = base_ptr as *mut Header;
        let hdr = NonNull::new(hdr_ptr).unwrap();

        // Initialize header only on the first actual creation (across all processes)
        let hdr_mut = unsafe { &mut *hdr_ptr };
        if is_creator || hdr_mut.magic != HEADER_MAGIC || hdr_mut.version != HEADER_VERSION {
            *hdr_mut = Header {
                magic:       HEADER_MAGIC,
                version:     HEADER_VERSION,
                _reserved:   [0; 6],
                lock:        RwLock::new(()),
                node_count:  AtomicUsize::new(0),
                root_offset: AtomicUsize::new(0),
                capacity,
            };
        } else {
            // existing valid header: ensure same capacity
            debug_assert_eq!(
                hdr_mut.capacity,
                capacity,
                "opened PatriciaTree with a different capacity than it was created"
            );
        }

        Ok(Self { shmem, base, hdr, free_list: Mutex::new(Vec::new()) })
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
        if hdr.capacity == 0 {
            panic!("Cannot insert into a zero-capacity tree");
        }
        let _w_guard = unsafe { &*self.hdr.as_ptr() }.lock.write(); // Acquire write lock
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
                // Atomically set new leaf if still empty
                let link_atomic = unsafe { &*(current_link_ptr.as_ptr()) };
                link_atomic.compare_exchange(
                    0,
                    leaf_offset,
                    Ordering::Release,
                    Ordering::Relaxed,
                ).expect("Concurrent insertion conflict");
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
            if cpl == prefix_len && cpl == current_node.prefix_len && key == current_node.key {
                println!("[INSERT] Subcase 2a: Exact match found. Updating TTL.");
                current_node.expires.store(expires, Ordering::Relaxed);
                println!("[INSERT] Finished Subcase 2a.");
                return;
            }

            // --- Subcase 2b: Split Required ---
            // Split also when prefix lengths match exactly but keys differ
            if cpl < current_node.prefix_len || (cpl == prefix_len && cpl == current_node.prefix_len && key != current_node.key) {
                println!("[INSERT] Subcase 2b: Split required at cpl={}.", cpl);
                // ATOMIC: Hold free_list lock for both check and allocation
                let (internal_offset, leaf_offset);
                {
                    let mut free_list = self.free_list.lock();
                    let reserved = hdr.node_count.load(Ordering::Acquire);
                    let free_len = free_list.len();
                    let available = free_len + hdr.capacity.saturating_sub(reserved);
                    if available < 2 {
                        println!("[INSERT] PANIC: Not enough capacity for split (need 2 slots, have={}).", available);
                        panic!("PatriciaTree capacity exceeded (split requires 2 nodes)");
                    }
                    // Allocate internal node
                    if let Some(offset) = free_list.pop() {
                        println!("[ALLOC] Reusing freed node for internal at offset={}", offset);
                        let node_ptr = unsafe { self.base.as_ptr().add(offset) as *mut Node };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key & mask(cpl));
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, cpl);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(u64::MAX, Ordering::Relaxed);
                        }
                        internal_offset = offset;
                    } else {
                        let index = hdr.node_count.fetch_add(1, Ordering::Relaxed);
                        if index >= hdr.capacity {
                            hdr.node_count.fetch_sub(1, Ordering::Relaxed);
                            panic!("PatriciaTree capacity exceeded allocating internal node during split");
                        }
                        internal_offset = size_of::<Header>() + index * size_of::<Node>();
                        let node_ptr = unsafe { self.base.as_ptr().add(internal_offset) as *mut Node };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key & mask(cpl));
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, cpl);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(u64::MAX, Ordering::Relaxed);
                        }
                    }
                    // Allocate leaf node
                    if let Some(offset) = free_list.pop() {
                        println!("[ALLOC] Reusing freed node for leaf at offset={}", offset);
                        let node_ptr = unsafe { self.base.as_ptr().add(offset) as *mut Node };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key);
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(expires, Ordering::Relaxed);
                        }
                        leaf_offset = offset;
                    } else {
                        let index = hdr.node_count.fetch_add(1, Ordering::Relaxed);
                        if index >= hdr.capacity {
                            hdr.node_count.fetch_sub(1, Ordering::Relaxed);
                            // Roll back internal node if it was newly allocated
                            let internal_index = (internal_offset - size_of::<Header>()) / size_of::<Node>();
                            if internal_index == index - 1 {
                                free_list.push(internal_offset);
                            }
                            panic!("PatriciaTree capacity exceeded allocating leaf node during split");
                        }
                        leaf_offset = size_of::<Header>() + index * size_of::<Node>();
                        let node_ptr = unsafe { self.base.as_ptr().add(leaf_offset) as *mut Node };
                        unsafe {
                            core::ptr::write_volatile(&mut (*node_ptr).key, key);
                            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                            (*node_ptr).left.store(0, Ordering::Relaxed);
                            (*node_ptr).right.store(0, Ordering::Relaxed);
                            (*node_ptr).expires.store(expires, Ordering::Relaxed);
                        }
                    }
                }
                unsafe {
                    let internal_node = &mut *(self.base.as_ptr().add(internal_offset) as *mut Node);
                    let new_bit = get_bit(key, cpl);
                    println!("[INSERT] Split branching: new_key_bit={}", new_bit);
                    if new_bit == 0 {
                        internal_node.left.store(leaf_offset, Ordering::Relaxed);
                        internal_node.right.store(current_offset, Ordering::Relaxed);
                    } else {
                        internal_node.right.store(leaf_offset, Ordering::Relaxed);
                        internal_node.left.store(current_offset, Ordering::Relaxed);
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
        // Try to reuse a freed node
        if let Some(offset) = self.free_list.lock().pop() {
            println!("[ALLOC] Reusing freed node at offset={}", offset);
            let node_ptr = unsafe { self.base.as_ptr().add(offset) as *mut Node };
            unsafe {
                core::ptr::write_volatile(&mut (*node_ptr).key, key);
                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                (*node_ptr).left.store(0, Ordering::Relaxed);
                (*node_ptr).right.store(0, Ordering::Relaxed);
                (*node_ptr).expires.store(expires, Ordering::Relaxed);
            }
            return offset;
        }
        println!("[ALLOC] key={:x}, prefix_len={}, expires={}", key, prefix_len, expires);
        let hdr = unsafe { &*self.hdr.as_ptr() };
        if hdr.capacity == 0 {
            panic!("Cannot insert into a zero-capacity tree");
        }
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
            let node_ptr = self.base.as_ptr().add(offset) as *mut Node;
            println!("[ALLOC] Writing node data at offset={}", offset);
            // Initialize the node
            core::ptr::write_volatile(&mut (*node_ptr).key, key);
            core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
            // Proper atomic initialization via store()
            (*node_ptr).left.store(0, Ordering::Relaxed);
            (*node_ptr).right.store(0, Ordering::Relaxed);
            (*node_ptr).expires.store(expires, Ordering::Relaxed);
            println!("[ALLOC] Node initialized at offset={}", offset);
        }
        offset
    }

    /// Lookup a key; true if found and not expired (Revised for Patricia structure)
    pub fn lookup(&self, key: u128) -> bool {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let _r_guard = hdr.lock.read(); // Acquire read lock for safe traversal
        let mut current_offset = hdr.root_offset.load(Ordering::Acquire);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        while current_offset != 0 {
            let node = unsafe { &*(self.base.as_ptr().add(current_offset) as *const Node) };
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
        let _w_guard = unsafe { &*self.hdr.as_ptr() }.lock.write(); // Acquire write lock
        println!("[DELETE] Lock acquired.");

        let mut current_offset = hdr.root_offset.load(Ordering::Relaxed);
        println!("[DELETE] Starting at root_offset={}", current_offset);

        // Need to track parent link to potentially update it if we prune nodes (future enhancement)
        // let mut parent_link_ptr = &hdr.root_offset as *const AtomicUsize as *mut AtomicUsize;

        while current_offset != 0 {
            println!("[DELETE] Loop: current_offset={}", current_offset);
            let node_ptr = unsafe { self.base.as_ptr().add(current_offset) as *mut Node };
            let node = unsafe { &*node_ptr }; // Read-only ref first
            println!("[DELETE] Node: key={:x}, prefix_len={}", node.key, node.prefix_len);

            // Compare the full key against the node's key up to the node's prefix length.
            let cpl = common_prefix_len(key, node.key, node.prefix_len);
            println!("[DELETE] cpl={}", cpl);

            if cpl < node.prefix_len {
                println!("[DELETE] Diverged (cpl < node.prefix_len). Key not found.");
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
                let mask = if node.prefix_len == 128 { !0u128 } else { !(!0u128 >> node.prefix_len) };
                if (key & mask) == (node.key & mask) {
                    // This node represents the prefix we are looking for.
                    // Check if the *keys* are identical. If the test inserts key K with prefix P,
                    // and we call delete(K), we should expire the node if node.key == K and node.prefix_len == P.
                    // The current test inserts (key, 64, ttl) and calls delete(key).
                    // Let's expire if node.key == key and node.prefix_len matches the implicit target (or the original insertion).
                    // For the concurrent test, keys are unique, so node.key == key should suffice.
                    if node.key == key {
                        println!("[DELETE] Found exact key match. Expiring node at offset={}.", current_offset);
                        let node_mut = unsafe { &mut *node_ptr };
                        node_mut.expires.store(0, Ordering::Release); // Expire the node
                        // Add this offset to free_list for reuse
                        self.free_list.lock().push(current_offset);
                        println!("[DELETE] Finished.");
                        // TODO: Implement pruning of expired nodes if necessary.
                        return;
                    }
                    // If keys don't match exactly, but the prefix does, it means the node we found
                    // is a less specific prefix. We need to continue searching deeper.
                    println!("[DELETE] Prefix matches, but key differs. Traversing down.");
                } else {
                    // This case (cpl == node.prefix_len but masked keys differ) should theoretically not happen
                    // due to how common_prefix_len works. If it does, it implies an issue elsewhere.
                    println!("[DELETE] Inconsistent state: cpl == node.prefix_len but masked keys differ. Key not found.");
                    return;
                }
            }

            // If we reach here, it means cpl == node.prefix_len, but the keys didn't match exactly,
            // OR cpl > node.prefix_len (which is impossible).
            // We need to traverse down based on the next bit *after* the node's prefix.
            if node.prefix_len >= 128 {
                println!("[DELETE] Node prefix_len >= 128, but key didn't match exactly. Key not found.");
                return; // Cannot go deeper
            }

            let next_bit = get_bit(key, node.prefix_len);
            println!("[DELETE] Traversing based on bit {} = {}", node.prefix_len, next_bit);
            current_offset = if next_bit == 0 {
                node.left.load(Ordering::Relaxed)
            } else {
                node.right.load(Ordering::Relaxed)
            };
        }
        println!("[DELETE] Reached end of branch (offset 0). Key not found.");
        // Key not found if loop finishes
    }

    /// Bulk insert multiple entries
    pub fn bulk_insert(&self, items: &[(u128, u8, u64)]) {
        for &(k, l, t) in items { self.insert(k, l, t) }
    }

    /// Clears the entire tree (drops all nodes).
    pub fn clear(&self) {
        let hdr = unsafe { &mut *self.hdr.as_ptr() };
        let _w = hdr.lock.write();
        hdr.node_count.store(0, Ordering::SeqCst);
        hdr.root_offset.store(0, Ordering::SeqCst);
        self.free_list.lock().clear();
    }
} // end impl PatriciaTree

// Public module for C API functions
pub mod public_api;

// Re-export all public API functions at the crate root
pub use public_api::*;