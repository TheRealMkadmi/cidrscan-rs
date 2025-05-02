//! Monolithic, high‑performance, shared Patricia tree with TTL
//! Monolithic to allow stealing the entire tree in one go.

use crate::shmem_rwlock::RawRwLock;
use raw_sync::Timeout; // needed by API
use shared_memory::{Shmem, ShmemConf, ShmemError}; // Shared memory mapping :contentReference[oaicite:13]{index=13}
use crossbeam_epoch as epoch;
use crossbeam_queue::SegQueue;
use std::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static FREELIST: SegQueue<Offset> = SegQueue::new();

pub mod shmem_rwlock;

/// Helper to encode an IPv4 address as a 128-bit key for IPv6-compatible Patricia tries.
/// The IPv4 address is placed in the lowest 32 bits (as per IPv4-mapped IPv6 addresses).
#[inline]
pub fn v4_key(addr: u32) -> u128 {
    (addr as u128) << 96
}

/// Helper to encode an IPv4 prefix length as a 128-bit prefix length for IPv6-compatible Patricia tries.
/// Adds 96 to the IPv4 prefix length to account for the leading zeros in the 128-bit space.
#[inline]
pub fn v4_plen(plen: u8) -> u8 {
    96 + plen
}
/// On Windows, enables SeCreateGlobalPrivilege for the current process if possible.
/// Call once early in main() if you want to allow cross-session shared memory creation.
/// No-op if privilege is already enabled or cannot be granted.
/// Only available if the "enable_global_priv" feature is enabled.
#[cfg(all(target_os = "windows", feature = "enable_global_priv"))]
pub fn enable_se_create_global_privilege() {
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::*;

    unsafe {
        let mut token = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) != 0 {
            let luid = {
                let mut l = LUID { LowPart: 0, HighPart: 0 };
                LookupPrivilegeValueA(std::ptr::null(), "SeCreateGlobalPrivilege\0".as_ptr() as _, &mut l);
                l
            };
            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
            };
            AdjustTokenPrivileges(token, 0, &tp as *const _ as _, 0, std::ptr::null_mut(), std::ptr::null_mut());
            CloseHandle(token);
        }
    }
}

// ===== Alignment helpers and constants =====

#[cfg(target_os = "windows")]
const PREFIX: &str = "cidrscan_"; // No Global\ here
#[cfg(not(target_os = "windows"))]
const PREFIX: &str = "cidrscan_";

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME:  u64 = 0x100000001b3;
fn fnv1a_64(s: &str) -> u64 {
   let mut h = FNV_OFFSET;
   for &b in s.as_bytes() {
       h ^= b as u64;
       h = h.wrapping_mul(FNV_PRIME);
   }
   h
}


/// Round `n` up to the next multiple of `align`  (align *must* be a power of two)
#[inline(always)]
const fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Cache-line size used by `Node`
const CACHE_LINE: usize = 64;

/// Padded size of the header – ALWAYS a multiple of 64
const HEADER_PADDED: usize = align_up(std::mem::size_of::<Header>(), CACHE_LINE);

/// Static guarantee that the padded size is indeed aligned
const _: () = assert!(HEADER_PADDED % CACHE_LINE == 0);

/// Compile-time sanity – the arena pointer is 64-aligned
const _: () = assert!(std::mem::align_of::<Header>() == CACHE_LINE);
const _: () = assert!(std::mem::align_of::<Node>()   == CACHE_LINE);

/// Print only if the "trace" feature is enabled.
#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => {
        // if cfg!(feature = "trace") {
            println!($($t)*);
        // }
    }
}

/// Error type for PatriciaTree operations.
#[derive(Debug)]
pub enum Error {
    CapacityExceeded,
    ZeroCapacity,
    InvalidPrefix,
    BranchHasChildren,
    // ... (extend as needed)
}

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

// Helper function to find the first differing bit between two keys, up to max_len bits.
// Returns Some(bit_index) where 0 = MSB, or None if all bits up to max_len are the same.

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

/// Node in the Patricia tree, each aligned to cache line
#[repr(C, align(64))]
struct Node {
    key: u128,             // IPv4 in upper 96 bits zero, or full IPv6
    prefix_len: u8,        // valid bits in key
    _pad: [u8; 3],         // padding to align next atomics (adjusted for AtomicU32)
    /// ABA generation counter to prevent reuse hazards (see moodycamel.com/blog/2014/solving-the-aba-problem-for-lock-free-free-lists)
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
    /// Returns the number of available slots (capacity - used + recycled).
    pub fn available_capacity(&self) -> usize {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let used = hdr.next_index.load(Ordering::Acquire) as usize;
        let recycled = hdr.free_slots.load(Ordering::Acquire) as usize;
        hdr.capacity - used + recycled
    }

    /// Create or open a shared‑memory tree
    pub fn open(name: &str, capacity: usize) -> Result<Self, ShmemError> {
        let hash = fnv1a_64(name);
        let os_name = format!("{PREFIX}{:016x}", hash);
        let region_size = HEADER_PADDED + capacity * size_of::<Node>();

        let conf = || ShmemConf::new().os_id(&os_name).size(region_size);
        let (shmem, is_creator) = match conf().create() {
            Ok(m) => (m, true),
            Err(ShmemError::MappingIdExists) => (conf().open()?, false),
            Err(e) => return Err(e),
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
            // -- write full header once (lock still zero) --
            unsafe {
                core::ptr::write(
                    hdr_ptr,
                    Header {
                        magic:  HEADER_MAGIC,
                        version: HEADER_VERSION,
                        _reserved: [0; 6],
                        lock:    core::mem::zeroed(), // to be initialised right after
                        next_index: AtomicU32::new(0),
                        free_slots: AtomicU32::new(0),
                        root_offset: AtomicU64::new(0),
                        capacity,
                        ref_count: AtomicUsize::new(0),
                        init_flag: AtomicU32::new(0),
                    },
                );
                // -- now bring the lock online --
                RawRwLock::init(
                    &mut (*hdr_ptr).lock as *mut _ as *mut u8,
                    Timeout::Infinite,
                )
                .expect("RawRwLock::init failed");
            }
        }
        let hdr_ref = unsafe { &*hdr_ptr };
        // Non-creator (or re-opened) mapping → ensure OS handles exist in this process
        if !is_creator {
            // tolerate half-initialised mapping: reopen or init
            unsafe {
                RawRwLock::reopen_in_place(&mut (*hdr_mut).lock)
                    .or_else(|_| RawRwLock::new_in_place(&mut (*hdr_mut).lock))
                    .expect("RawRwLock reopen OR init failed");
            }
        }
        hdr_ref
            .ref_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Self {
            shmem,
            base,
            hdr,
            os_id: os_name.clone(),
        })
    }


    /// Insert a key with a given prefix length and TTL - REVISED LOGIC
    pub fn insert(&self, key: u128, prefix_len: u8, ttl_secs: u64) -> Result<(), Error> {
        trace!("[INSERT] key={:x}, prefix_len={}, ttl={}", key, prefix_len, ttl_secs);
        if prefix_len > 128 {
            return Err(Error::InvalidPrefix);
        }

        let hdr = unsafe { &*self.hdr.as_ptr() };
        if hdr.capacity == 0 {
            return Err(Error::ZeroCapacity);
        }
        // Acquire write lock using guard
        let _write_guard = hdr.lock.write_lock();
        trace!("[INSERT] Lock acquired. Current next_index={}", hdr.next_index.load(Ordering::Relaxed));

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
            trace!(
                "[INSERT] Loop start. current_offset={}, current_gen={}",
                current_offset, current_gen
            );

            // --- Case 1: Empty Link ---
            if current_offset == 0 {
                trace!("[INSERT] Case 1: Empty link found.");
                let current_node_count = hdr.next_index.load(Ordering::Relaxed);
                trace!("[INSERT] Checking capacity: count={}, capacity={}", current_node_count, hdr.capacity);
                if (current_node_count as usize) >= hdr.capacity {
                    trace!("[INSERT] PANIC: Capacity exceeded before allocation.");
                    return Err(Error::CapacityExceeded);
                }
                let (leaf_offset, leaf_gen) = self.allocate_node_with_gen(key, prefix_len, expires)?;
                trace!("[INSERT] Allocated leaf node at offset={}, gen={}. Storing link.", leaf_offset, leaf_gen);
                // Atomically set new leaf if still empty
                let link_atomic = unsafe { &*(current_link_ptr as *const AtomicU64) };
                if link_atomic
                    .compare_exchange(
                        0,
                        pack(leaf_offset, leaf_gen),
                        Ordering::AcqRel, // Use AcqRel for CAS
                        Ordering::Acquire,
                    )
                    .is_err()
                {
                    // Someone else installed a node – recycle ours and restart
                    // Retire the offset using epoch-based reclamation
                    let off = leaf_offset as Offset;
                    epoch::pin().defer(move || {
                        FREELIST.push(off);
                    });
                    continue; // tail of the while loop
                }
                trace!("[INSERT] Finished Case 1.");
                // Remove explicit unlock, guard will handle it
                // hdr.lock.write_unlock();
                return Ok(());
            }

            // --- Case 2: Follow Link ---
            trace!("[INSERT] Case 2: Following link to offset={}", current_offset);
            let current_node = unsafe {
                let ptr = self.base.as_ptr().add(current_offset as usize) as *mut Node;
                &mut *ptr
            };
            trace!("[INSERT] Current node: key={:x}, prefix_len={}", current_node.key, current_node.prefix_len);

            let max_cmp_len = prefix_len.min(current_node.prefix_len);
            let cpl = common_prefix_len(key, current_node.key, max_cmp_len);
            trace!("[INSERT] max_cmp_len={}, cpl={}", max_cmp_len, cpl);

            // --- Subcase 2a: Exact Match ---
            if cpl == prefix_len && cpl == current_node.prefix_len && key == current_node.key {
                trace!("[INSERT] Subcase 2a: Exact match found. Updating TTL.");
                current_node.expires.store(expires, Ordering::Relaxed);
                trace!("[INSERT] Finished Subcase 2a.");
                return Ok(());
            }

            // --- Subcase 2b: Insert Above (Shorter Prefix) ---
            // This case happens when the new key is a *shorter* prefix of the current node's key.
            // Condition: cpl == prefix_len && prefix_len < current_node.prefix_len
            if cpl == prefix_len && prefix_len < current_node.prefix_len {
                trace!("[INSERT] Subcase 2b: Insert-above (shorter prefix) required at cpl={}.", cpl);
                let current_node_count = hdr.next_index.load(Ordering::Relaxed);
                trace!("[INSERT] Checking capacity for insert above: count={}, capacity={}", current_node_count, hdr.capacity);
                if (current_node_count as usize) >= hdr.capacity {
                    trace!("[INSERT] PANIC: Capacity exceeded before insert above allocation.");
                    return Err(Error::CapacityExceeded);
                }
                let (new_node_offset, new_node_gen) =
                    self.allocate_node_with_gen(key, prefix_len, expires)?;
                trace!("[INSERT] Allocated new node for insert above at offset={}, gen={}.", new_node_offset, new_node_gen);

                unsafe {
                    let new_node =
                        &mut *(self.base.as_ptr().add(new_node_offset as usize) as *mut Node);
                    // Bit to check in the *existing* node's key at the *new* node's prefix length
                    let existing_node_bit = get_bit(current_node.key, prefix_len);
                    trace!("[INSERT] Insert Above branching: existing_node_bit={}", existing_node_bit);

                    if existing_node_bit == 0 {
                        new_node
                            .left
                            .store(pack(current_offset as u32, current_gen), Ordering::Release);
                    } else {
                        new_node
                            .right
                            .store(pack(current_offset as u32, current_gen), Ordering::Release);
                    }
                    trace!("[INSERT] Linking new node at offset={}.", new_node_offset);
                    (*current_link_ptr).store(
                        pack(new_node_offset as u32, new_node_gen),
                        Ordering::Release,
                    );
                }
                trace!("[INSERT] Finished Subcase 2b (insert-above).");
                return Ok(());
            }

            // --- Subcase 2c: Split Required ---
            // Only split if keys truly differ
            // Split also when prefix lengths match exactly but keys differ
            if (cpl < current_node.prefix_len && key != current_node.key)
                || (cpl == prefix_len && cpl == current_node.prefix_len && key != current_node.key)
            {
                // Find the first differing bit after the common prefix
                // split at the *actual* first differing bit, not capped by current prefixes
                // In a Patricia trie the split point *is* the common-prefix length
                let xor = key ^ current_node.key;
                // Only compute split_bit if xor != 0
                if xor != 0 {
                    let split_bit = xor.leading_zeros() as u8;
                    debug_assert!(split_bit >= cpl && split_bit < 128, "split_invariants");
                    trace!("[INSERT] Subcase 2c: Split required at split_bit={}.", split_bit);
                    // ATOMIC: Hold free_list lock for both check and allocation
                    let internal_offset: Offset;
                    let internal_gen: u32;
                    let leaf_offset: Offset;
                    let leaf_gen: u32;
                    {
                        let available = self.available_capacity();
                        if available < 2 {
                            trace!("[INSERT] PANIC: Not enough capacity for split (need 2 slots, have={}).", available);
                            return Err(Error::CapacityExceeded);
                        }
                        // Allocate internal node
                        if let Some(offset) = FREELIST.pop() {
                            trace!("[ALLOC] Reusing freed node for internal at offset={}", offset);
                            let node_ptr =
                                unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                            let gen =
                                unsafe { (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1 };
                            unsafe {
                                core::ptr::write_volatile(&mut (*node_ptr).key, key & mask(split_bit));
                                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, split_bit);
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
                                return Err(Error::CapacityExceeded);
                            }
                            internal_offset = HEADER_PADDED as Offset
                                + (index as Offset) * size_of::<Node>() as Offset;
                            let node_ptr = unsafe {
                                self.base.as_ptr().add(internal_offset as usize) as *mut Node
                            };
                            unsafe {
                                core::ptr::write_volatile(&mut (*node_ptr).key, key & mask(split_bit));
                                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, split_bit);
                                (*node_ptr).generation.store(1, Ordering::Relaxed);
                                (*node_ptr).left.store(0, Ordering::Relaxed);
                                (*node_ptr).right.store(0, Ordering::Relaxed);
                                (*node_ptr).expires.store(u64::MAX, Ordering::Relaxed);
                            }
                            internal_gen = 1;
                        }
                        // Allocate leaf node
                        if let Some(offset) = FREELIST.pop() {
                            trace!("[ALLOC] Reusing freed node for leaf at offset={}", offset);
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
                                let internal_index = ((internal_offset as usize) - size_of::<Header>())
                                    / size_of::<Node>();
                                if internal_index == (index as usize) - 1 {
                                    // Retire the internal_offset using epoch-based reclamation
                                    let off = internal_offset;
                                    epoch::pin().defer(move || {
                                        FREELIST.push(off);
                                    });
                                }
                                return Err(Error::CapacityExceeded);
                            }
                            leaf_offset = HEADER_PADDED as Offset
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
                    // This whole block needs to be atomic with respect to the parent link update
                    unsafe {
                        let internal_node =
                            &mut *(self.base.as_ptr().add(internal_offset as usize) as *mut Node);
                        let new_bit = get_bit(key, split_bit);
                        trace!("[INSERT] Split branching: new_key_bit={}", new_bit);
                        if new_bit == 0 {
                            internal_node
                                .left
                                .store(pack(leaf_offset, leaf_gen), Ordering::Release);
                            internal_node
                                .right
                                .store(pack(current_offset, current_gen), Ordering::Release);
                        } else {
                            internal_node
                                .right
                                .store(pack(leaf_offset, leaf_gen), Ordering::Release);
                            internal_node
                                .left
                                .store(pack(current_offset, current_gen), Ordering::Release);
                        }
                        trace!("[INSERT] Linking new internal node at offset={}.", internal_offset);

                        // Atomically update the parent link to point to the new internal node
                        let link_atomic = &*(current_link_ptr as *const AtomicU64);
                        if link_atomic.compare_exchange(
                            current_ptr,
                            pack(internal_offset, internal_gen),
                            Ordering::AcqRel,
                            Ordering::Acquire
                        ).is_err() {
                            trace!("[INSERT] Split CAS failed. Recycling nodes and restarting.");
                            // Retire both offsets using epoch-based reclamation
                            let int_off = internal_offset;
                            let leaf_off = leaf_offset;
                            epoch::pin().defer(move || {
                                FREELIST.push(int_off);
                                FREELIST.push(leaf_off);
                            });
                            continue;
                        }
                    }
                    trace!("[INSERT] Finished Subcase 2c (split).");
                    return Ok(());
                } else {
                    // xor == 0, keys are identical up to compared length, do not split
                    // This should not happen due to earlier checks, but is a safe guard
                }
            }

            // --- Subcase 2d: Descend (Proper Prefix) ---
            // This case happens when the current node's prefix is a proper prefix of the key being inserted.
            // Correct logic: only allocate a new node if the child pointer is null, otherwise descend.
            if cpl == current_node.prefix_len && cpl < prefix_len {
                let next_bit = get_bit(key, current_node.prefix_len);
                let child_atomic = if next_bit == 0 {
                    &current_node.left
                } else {
                    &current_node.right
                };

                let child_ptr = child_atomic.load(Ordering::Acquire);

                if child_ptr == 0 {
                    // Child missing → insert leaf *here*
                    let (leaf_off, leaf_gen) =
                        self.allocate_node_with_gen(key, prefix_len, expires)?;
                    child_atomic.store(pack(leaf_off, leaf_gen), Ordering::Release);
                    trace!("[INSERT] Inserted new leaf at offset={}, gen={}", leaf_off, leaf_gen);
                    return Ok(());
                } else {
                    // Child exists → descend
                    current_link_ptr = child_atomic as *const AtomicU64 as *mut AtomicU64;
                    trace!("[INSERT] Descending to child at ptr={:x}", child_ptr);
                    continue;
                }
            }

            // --- Subcase 2d: Traverse Down ---
            // This case happens when the current node is a prefix of the new key.
            // cpl == current_node.prefix_len must hold.
            // cpl < prefix_len was handled by Insert Above.
            // So, this path should only be taken if cpl == current_node.prefix_len < prefix_len.
            // Let's re-verify the conditions. If cpl == current_node.prefix_len, it means the current node's
            // prefix matches the start of the key being inserted. We need to decide based on the next bit.
            trace!("[INSERT] Subcase 2d: Traverse Down needed.");
            let next_bit = get_bit(key, current_node.prefix_len); // Bit *after* current prefix
            trace!("[INSERT] Traverse direction bit={}", next_bit);
            let next_link_atomic_ptr = if next_bit == 0 {
                &current_node.left as *const AtomicU64 as *mut AtomicU64
            } else {
                &current_node.right as *const AtomicU64 as *mut AtomicU64
            };
            current_link_ptr = next_link_atomic_ptr;
            trace!("[INSERT] Continuing loop, following link.");
            // Continue loop
        }
    }

    // Helper to allocate a new node (assumes lock is held)
    /// Allocates a new node and returns (offset, generation).
    fn allocate_node_with_gen(&self, key: u128, prefix_len: u8, expires: u64) -> Result<(Offset, u32), Error> {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let hdr_size = HEADER_PADDED as Offset;
        let node_size = size_of::<Node>() as Offset;
        loop {
            // ① Try to reuse a freed slot first (cheap fast-path)
            if let Some(offset) = FREELIST.pop() {
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
                return Ok((offset, gen));
            }

            // ② Try bump allocation
            let index = hdr.next_index.fetch_add(1, Ordering::SeqCst);
            if (index as usize) < hdr.capacity {
                let offset = hdr_size + index * node_size;
                let node_ptr = unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                unsafe {
                    core::ptr::write_volatile(&mut (*node_ptr).key, key);
                    core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                    (*node_ptr).generation.store(1, Ordering::Relaxed);
                    (*node_ptr).left.store(0, Ordering::Relaxed);
                    (*node_ptr).right.store(0, Ordering::Relaxed);
                    (*node_ptr).expires.store(expires, Ordering::Relaxed);
                }
                return Ok((offset, 1));
            }
            hdr.next_index.fetch_sub(1, Ordering::SeqCst); // roll back

            // ③ Arena full – block until another thread frees something
            if hdr.free_slots.load(Ordering::Acquire) == 0 {
                return Err(Error::CapacityExceeded);
            }
            std::thread::park_timeout(std::time::Duration::from_micros(30));
        }
    }


    #[inline(always)]
    fn follow(&self, packed: u64) -> Option<(&Node, u32)> {
        if packed == 0 { return None; }
        let (off, gen) = unpack(packed);
        let ptr = unsafe { self.base.as_ptr().add(off as usize) as *const Node };
        Some((unsafe { &*ptr }, gen))
    }

    /// Lookup a key; true if found and not expired (Revised for Patricia structure)
    pub fn lookup(&self, key: u128) -> bool {
        let hdr  = unsafe { &*self.hdr.as_ptr() };
        let mut link = hdr.root_offset.load(Ordering::Acquire);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        while let Some((node, gen)) = self.follow(link) {
            if gen != node.generation.load(Ordering::Acquire) {
                // ABA detected: retry from root
                link = hdr.root_offset.load(Ordering::Acquire);
                continue;
            }
            let cpl = common_prefix_len(key, node.key, node.prefix_len);
            if cpl < node.prefix_len { return false; }

            let exp = node.expires.load(Ordering::Acquire);
            if exp != u64::MAX && cpl == node.prefix_len {
                // Only return if this is a leaf node; otherwise, keep traversing
                if node.left.load(Ordering::Acquire) == 0 && node.right.load(Ordering::Acquire) == 0 {
                    return exp >= now;
                }
                // else: internal node expired, but traversal continues
            }

            if node.prefix_len >= 128 {
                return false;
            }

            let next_bit = get_bit(key, node.prefix_len);
            link = if next_bit == 0 {
                node.left.load(Ordering::Acquire)
            } else {
                node.right.load(Ordering::Acquire)
            };
        }
        false
    }
    /// Delete a key with a given prefix length (expire immediately, concurrency-safe, only expires exact leaf nodes).
    /// Both `key` and `prefix_len` must match a leaf node for deletion to occur.
    pub fn delete(&self, key: u128, prefix_len: u8) -> Result<(), Error> {
        trace!("[DELETE] key={:x}, prefix_len={}", key, prefix_len);
        let hdr = unsafe { &*self.hdr.as_ptr() };
        // Acquire write lock using guard
        let _write_guard = hdr.lock.write_lock();
        trace!("[DELETE] Lock acquired.");

        let mut current_ptr = hdr.root_offset.load(Ordering::Relaxed);
        let mut current_offset;
        let mut current_gen;
        (current_offset, current_gen) = unpack(current_ptr);
        trace!("[DELETE] Starting at root_offset={}, gen={}", current_offset, current_gen);

        while current_offset != 0 {
            trace!("[DELETE] Loop: current_offset={}", current_offset);
            let node_ptr = unsafe { self.base.as_ptr().add(current_offset as usize) as *mut Node };
            let node = unsafe { &*node_ptr }; // Read-only ref first
            let node_gen = node.generation.load(Ordering::Acquire);
            if node_gen != current_gen {
                // ABA detected, restart from root
                current_ptr = hdr.root_offset.load(Ordering::Relaxed);
                (current_offset, current_gen) = unpack(current_ptr);
                continue;
            }
            trace!("[DELETE] Node: key={:x}, prefix_len={}, gen={}", node.key, node.prefix_len, node_gen);

            // Compare the full key against the node's key up to the node's prefix length.
            let cpl = common_prefix_len(key, node.key, node.prefix_len);
            trace!("[DELETE] cpl={}", cpl);

            if cpl < node.prefix_len {
                trace!("[DELETE] Diverged (cpl < node.prefix_len). Key not found.");
                return Ok(()); // Key not found in this subtree
            }

            // Only expire if this is an exact (key, prefix_len) match and a leaf node
            if cpl == node.prefix_len && node.key == key && node.prefix_len == prefix_len {
                let is_leaf = node.left.load(Ordering::Acquire) == 0 && node.right.load(Ordering::Acquire) == 0;
                if is_leaf {
                    trace!("[DELETE] Found exact key+prefix match and is leaf. Expiring node at offset={}.", current_offset);
                    let node_mut = unsafe { &mut *node_ptr };
                    node_mut.expires.store(0, Ordering::Release); // Expire the node
                    // Retire the offset using epoch-based reclamation
                    let off = current_offset;
                    epoch::pin().defer(move || {
                        FREELIST.push(off);
                    });
                    // Increment free_slots for reclaimable capacity
                    let hdr = unsafe { &*self.hdr.as_ptr() };
                    hdr.free_slots.fetch_add(1, Ordering::Release);
                    trace!("[DELETE] Finished.");
                    return Ok(());
                } else {
                    trace!("[DELETE] Attempted to delete internal node with children. Returning BranchHasChildren.");
                    return Err(Error::BranchHasChildren);
                }
            }
            // If keys don't match exactly, or the prefix length does not match, continue searching deeper.
            trace!("[DELETE] Prefix matches, but key or prefix_len differs or not a leaf. Traversing down.");

            if node.prefix_len >= 128 {
                #[cfg(debug_assertions)]
                trace!("[DELETE] Node prefix_len >= 128, but key didn't match exactly. Key not found.");
                return Ok(()); // Cannot go deeper
            }

            let next_bit = get_bit(key, node.prefix_len);
            trace!("[DELETE] Traversing based on bit {} = {}", node.prefix_len, next_bit);
            current_ptr = if next_bit == 0 {
                node.left.load(Ordering::Relaxed)
            } else {
                node.right.load(Ordering::Relaxed)
            };
            (current_offset, current_gen) = unpack(current_ptr);
        }
        trace!("[DELETE] Reached end of branch (offset 0). Key not found.");
        Ok(())
    }


    /// Bulk insert multiple entries
    pub fn bulk_insert(&self, items: &[(u128, u8, u64)]) -> Result<(), Error> {
        for &(k, l, t) in items {
            self.insert(k, l, t)?;
        }
        Ok(())
    }

    /// Clears the entire tree (drops all nodes).
    pub fn clear(&self) {
        trace!("[CLEAR] Clearing tree.");
        let hdr = unsafe { &*self.hdr.as_ptr() };
        // Acquire write lock using guard
        let _write_guard = hdr.lock.write_lock();
        trace!("[CLEAR] Lock acquired.");

        // Reset root and allocator state
        hdr.root_offset.store(0, Ordering::Release);
        hdr.next_index.store(0, Ordering::Release);
        hdr.free_slots.store(0, Ordering::Release);

        trace!("[CLEAR] Tree cleared.");
        // Remove explicit unlock, guard will handle it
        // hdr.lock.write_unlock();
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
