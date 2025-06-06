pub mod constants;
pub mod errors;
pub mod handle_registry;
pub mod helpers;
pub mod platform;
pub mod shmem_rwlock;
pub mod telemetry;
pub mod types;

#[cfg(all(target_os = "windows", feature = "enable_global_priv"))]
pub use crate::platform::windows::enable_se_create_global_privilege;

// Install metrics recorder when the crate is loaded
#[doc(hidden)]
#[inline(always)]
fn _telemetry_bootstrap() {
    telemetry::init();
}

// NB: reference forces the function to run during `.so` load
#[used]
static _BOOTSTRAP: fn() = _telemetry_bootstrap;

use constants::*;
use crossbeam_queue::SegQueue;
#[cfg(unix)]
use crate::platform::unix::make_os_id;
#[cfg(target_os = "windows")]
use crate::platform::windows::make_os_id;
use helpers::*;
use types::Offset;
use crate::errors::Error;
use types::*;
use crate::shmem_rwlock::RawRwLock;
use crossbeam_epoch as epoch;
use log::{debug, error, info, trace, warn};
use metrics::{counter, gauge};
use once_cell::sync::OnceCell;
use raw_sync::Timeout; // needed by API
use shared_memory::{ShmemConf, ShmemError};
use std::sync::Arc;
use std::{
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
    cell::Cell,
};




// ===== Compile-time assertions for alignment and size =====
const HEADER_PADDED: usize =
    helpers::align_up(std::mem::size_of::<types::Header>(), constants::CACHE_LINE);
const _: () = assert!(HEADER_PADDED % constants::CACHE_LINE == 0);
const _: () = assert!(std::mem::align_of::<types::Header>() == constants::CACHE_LINE);
const _: () = assert!(std::mem::align_of::<types::Node>() == constants::CACHE_LINE);

#[allow(dead_code)]
impl PatriciaTree {
    // ---- logging bootstraper -------------------------------------------------
    fn ensure_logging() {
        static INIT: OnceCell<()> = OnceCell::new();
        INIT.get_or_init(|| {
            // Fallback: simple env_logger with RFC‑3339 ts off.
            let _ = env_logger::builder()
                .format_timestamp(None)
                .is_test(std::env::var("RUST_TEST_THREADS").is_ok())
                .try_init();
        });
    }

    /// Helper to retire an offset safely for epoch-based reclamation.
    pub fn retire_offset(&self, off: Offset) {
        let cur = self.local_epoch.get();
        let stamped: u64 = ((cur & 0xFFFF_FFFF) << 32) | off as u64;
        self.freelist.push(stamped);
    }
    /// Insert an IPv4 prefix (automatically maps the 32-bit address into the high 96 bits).
    pub fn insert_v4(&self, addr: u32, prefix_len: u8, ttl_secs: u64) -> Result<(), Error> {
        let key = v4_key(addr);
        let plen128 = v4_plen(prefix_len);
        self.insert(key, plen128, ttl_secs, None)
    }

    /// Delete an IPv4 prefix.
    pub fn delete_v4(&self, addr: u32, prefix_len: u8) -> Result<(), Error> {
        let key = v4_key(addr);
        let plen128 = v4_plen(prefix_len);
        self.delete(key, plen128)
    }

    /// Lookup an IPv4 address against stored prefixes, returning match info if found.
    pub fn lookup_v4(&self, addr: u32) -> Option<Match<'_>> {
        let key = v4_key(addr);
        self.lookup(key)
    }

    /// Returns the number of available slots (capacity - used + recycled).
    pub fn available_capacity(&self) -> usize {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let used = hdr.next_index.load(Ordering::Acquire) as usize;
        let recycled = self.freelist.len();
        hdr.capacity - used + recycled
    }

    /// Emit gauges periodically (caller decides cadence).
    pub fn report_capacity_metrics(&self) {
        let free = self.available_capacity() as f64;
        gauge!("cidrscan_free_slots").set(free);
    }

    /// Create or open a shared‑memory tree
    pub fn open(name: &str, capacity: usize) -> Result<Self, ShmemError> {
        Self::ensure_logging();
        // hard-cap: header + nodes + tags must still addressable by u32
        let max_nodes = (u32::MAX as usize) / size_of::<Node>();
        if capacity > max_nodes {
            return Err(ShmemError::MapOpenFailed(72)); // “capacity too large”
        }
        let hash = fnv1a_64(name);
        let os_name = make_os_id(PREFIX, hash);
        let region_size = HEADER_PADDED + capacity * size_of::<Node>() + capacity * TAG_MAX_LEN;

        let conf = || ShmemConf::new().os_id(&os_name).size(region_size);
        let (shmem, is_creator) = match conf().create() {
            Ok(m) => (m, true),
            Err(ShmemError::MappingIdExists) => (conf().open()?, false),
            Err(e) => return Err(e),
        };

        let base_ptr = shmem.as_ptr() as *mut u8;
        let base = NonNull::new(base_ptr).ok_or_else(|| ShmemError::MapOpenFailed(70))?;
        let hdr_ptr = base_ptr as *mut Header;
        let hdr = NonNull::new(hdr_ptr).ok_or_else(|| ShmemError::MapOpenFailed(71))?;
        let hdr_mut = unsafe { &mut *hdr_ptr };

        let tag_base_ptr = unsafe {
            base.as_ptr()
                .add(HEADER_PADDED + capacity * size_of::<Node>())
        };
        let tag_base = NonNull::new(tag_base_ptr).expect("tag_base_ptr is null in PatriciaTree::open");

        // === PATCH 1: Header parameter mismatch guard ===
        if !is_creator {
            if hdr_mut.version != HEADER_VERSION || hdr_mut.capacity != capacity {
                // Return error if version or capacity mismatches
                return Err(ShmemError::MapOpenFailed(69));
            }
        }

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
                        magic: HEADER_MAGIC,
                        version: HEADER_VERSION,
                        _reserved: [0; 6],
                        lock_init: AtomicU8::new(0),
                        lock: core::mem::zeroed(), // to be initialised right after
                        next_index: AtomicU32::new(0),
                        free_slots: AtomicU32::new(0),
                        root_offset: AtomicU64::new(0),
                        capacity,
                        ref_count: AtomicUsize::new(0),
                        global_epoch: AtomicU64::new(0), // <── NEW
                        init_flag: AtomicU32::new(0),
                    },
                );
            }
        }
        if is_creator { hdr_mut.global_epoch.store(1, Ordering::Release); }
        let prev = hdr_mut.lock_init.fetch_or(1, Ordering::AcqRel);
        if prev == 0 {
            // first opener in this process: initialise the bytes
            unsafe {
                RawRwLock::new_in_place((&mut hdr_mut.lock).as_mut_ptr())
                    .map_err(|_| ShmemError::MapOpenFailed(73))?;
            }
        } else {
            // subsequent opens: attach to existing lock state
            unsafe {
                RawRwLock::reopen_in_place((&mut hdr_mut.lock).as_mut_ptr())
                    .map_err(|_| ShmemError::MapOpenFailed(74))?;
            }
        }
        let hdr_ref = unsafe { &*hdr_ptr };
        hdr_ref
            .ref_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        // -------- ❶  startup epoch flush – reclaims slots of dead processes --
        epoch::pin().flush();

        Ok(Self {
            shmem,
            base,
            tag_base,
            hdr,
            os_id: os_name.clone(),
            freelist: Arc::new(SegQueue::new()),
            local_epoch: Cell::new(0),
        })
    }

    // ------------------------------------------------------------------- //
    // ❷  Manual flush for ops – call from a cron job or admin endpoint
    // ------------------------------------------------------------------- //
    /// Execute pending epoch callbacks *now* and push recycled offsets
    /// into the freelist.  Cheap (< 1 µs) and wait‑free for other threads.
    pub fn flush(&self) {
        let g = unsafe { &*self.hdr.as_ptr() }.global_epoch.fetch_add(1, Ordering::AcqRel) + 1;
        self.local_epoch.set(g);

        // reclaim if two full epochs have passed
        while let Some(raw) = self.freelist.pop() {
            let node_epoch = raw >> 32;
            if g.wrapping_sub(node_epoch) < 2 { self.freelist.push(raw); break }
            // real reclaim:
            self.free_node((raw & 0xFFFF_FFFF) as u64);
        }
    }

    /// Insert a key with a given prefix length and TTL
    pub fn insert(&self, key: u128, prefix_len: u8, ttl_secs: u64, tag: Option<&str>) -> Result<(), Error> {
        counter!("cidrscan_inserts_total").increment(1);
        info!(
            "[INSERT] key={:x}, prefix_len={}, ttl={}",
            key,
            prefix_len,
            ttl_secs
        );
        if prefix_len > 128 {
            return Err(Error::InvalidPrefix);
        }

        let hdr = unsafe { &*self.hdr.as_ptr() };
        if hdr.capacity == 0 {
            return Err(Error::ZeroCapacity);
        }
        // Acquire write lock using guard
        let _write_guard = unsafe {
            hdr.lock.assume_init_ref().write_lock()
                .map_err(|e| Error::Lock(format!("write_lock failed: {e}")))?
        };
        debug!(
            "[INSERT] Lock acquired. Current next_index={}",
            hdr.next_index.load(Ordering::Relaxed)
        );

        // Store canonical key
        let stored_key = canonical(key, prefix_len);

        let expires = if ttl_secs == 0 {
            u64::MAX
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("SystemTime before UNIX_EPOCH in insert; system clock is invalid")
                .as_secs()
                .saturating_add(ttl_secs)
        };

        let mut current_link_ptr = &hdr.root_offset as *const AtomicU64 as *mut AtomicU64;

        loop {
            let current_ptr = unsafe { (*current_link_ptr).load(Ordering::Relaxed) };
            let (current_offset, current_gen) = unpack(current_ptr);
            trace!(
                "[INSERT] Loop start. current_offset={}, current_gen={}",
                current_offset,
                current_gen
            );

            // --- Case 1: Empty Link ---
            if current_offset == 0 {
                trace!("[INSERT] Case 1: Empty link found.");
                let current_node_count = hdr.next_index.load(Ordering::Relaxed);
                trace!(
                    "[INSERT] Checking capacity: count={}, capacity={}",
                    current_node_count,
                    hdr.capacity
                );
                if (current_node_count as usize) >= hdr.capacity {
                    error!("[INSERT] PANIC: Capacity exceeded before allocation.");
                    return Err(Error::CapacityExceeded);
                }
                let (leaf_offset, leaf_gen, _) =
                    self.alloc_node(stored_key, prefix_len, expires, tag)?;
                debug!(
                    "[INSERT] Allocated leaf node at offset={}, gen={}. Storing link.",
                    leaf_offset,
                    leaf_gen
                );
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
                    // No free_slots update needed here, as this is a failed allocation rollback
                    self.retire_offset(off);
                    continue; // tail of the while loop
                }
                debug!("[INSERT] Finished Case 1.");
                // Remove explicit unlock, guard will handle it
                // hdr.lock.write_unlock();
                return Ok(());
            }

            // --- Case 2: Follow Link ---
            trace!(
                "[INSERT] Case 2: Following link to offset={}",
                current_offset
            );
            let current_node = unsafe {
                let ptr = self.base.as_ptr().add(current_offset as usize) as *mut Node;
                &mut *ptr
            };
            trace!(
                "[INSERT] Current node: key={:x}, prefix_len={}",
                current_node.key,
                current_node.prefix_len
            );

            let max_cmp_len = prefix_len.min(current_node.prefix_len);
            let cpl = common_prefix_len(stored_key, current_node.key, max_cmp_len);
            trace!("[INSERT] max_cmp_len={}, cpl={}", max_cmp_len, cpl);

            // --- Subcase 2a: Exact Match (full key) ---
            if cpl == prefix_len && cpl == current_node.prefix_len && stored_key == current_node.key
            {
                debug!("[INSERT] Subcase 2a: Exact match found (full key). Updating TTL.");
                current_node.expires.store(expires, Ordering::Relaxed);
                current_node.is_terminal.store(1, Ordering::Release); // mark as stored
                current_node.refcnt.fetch_add(1, Ordering::AcqRel); // increment multiplicity
                debug!("[INSERT] Finished Subcase 2a.");
                return Ok(());
            }

            // --- Subcase 2b: Insert Above (Shorter Prefix) ---
            // This case happens when the new key is a *shorter* prefix of the current node's key.
            // Condition: cpl == prefix_len && prefix_len < current_node.prefix_len
            if cpl == prefix_len && prefix_len < current_node.prefix_len {
                debug!(
                    "[INSERT] Subcase 2b: Insert-above (shorter prefix) required at cpl={}.",
                    cpl
                );
                let current_node_count = hdr.next_index.load(Ordering::Relaxed);
                trace!(
                    "[INSERT] Checking capacity for insert above: count={}, capacity={}",
                    current_node_count,
                    hdr.capacity
                );
                if (current_node_count as usize) >= hdr.capacity {
                    error!("[INSERT] PANIC: Capacity exceeded before insert above allocation.");
                    return Err(Error::CapacityExceeded);
                }
                let (new_node_offset, new_node_gen, _) =
                    self.alloc_node(stored_key, prefix_len, expires, tag)?;
                debug!(
                    "[INSERT] Allocated new node for insert above at offset={}, gen={}.",
                    new_node_offset,
                    new_node_gen
                );

                unsafe {
                    let new_node =
                        &mut *(self.base.as_ptr().add(new_node_offset as usize) as *mut Node);
                    // Bit to check in the *existing* node's key at the *new* node's prefix length
                    let existing_node_bit = get_bit(current_node.key, prefix_len);
                    trace!(
                        "[INSERT] Insert Above branching: existing_node_bit={}",
                        existing_node_bit
                    );

                    if existing_node_bit == 0 {
                        new_node
                            .left
                            .store(pack(current_offset as u32, current_gen), Ordering::Release);
                    } else {
                        new_node
                            .right
                            .store(pack(current_offset as u32, current_gen), Ordering::Release);
                    }
                    debug!("[INSERT] Linking new node at offset={}.", new_node_offset);
                    new_node.is_terminal.store(1, Ordering::Release); // Mark insert-above node as terminal
                    (*current_link_ptr).store(
                        pack(new_node_offset as u32, new_node_gen),
                        Ordering::Release,
                    );
                }
                debug!("[INSERT] Finished Subcase 2b (insert-above).");
                return Ok(());
            }

            // --- Subcase 2c: Split Required ---
            // Only split if keys truly differ
            // Split also when prefix lengths match exactly but keys differ
            if cpl < current_node.prefix_len && stored_key != current_node.key
            {
                // Find the first differing bit after the common prefix
                // split at the *actual* first differing bit, not capped by current prefixes
                // In a Patricia trie the split point *is* the common-prefix length
                let xor = stored_key ^ current_node.key;
                // Only compute split_bit if xor != 0
                if xor != 0 {
                    let split_bit = xor.leading_zeros() as u8;
                    debug_assert!(split_bit >= cpl && split_bit < 128, "split_invariants");
                    debug!(
                        "[INSERT] Subcase 2c: Split required at split_bit={}.",
                        split_bit
                    );
                    // ATOMIC: Hold free_list lock for both check and allocation
                    let internal_offset: Offset;
                    let internal_gen: u32;
                    let leaf_offset: Offset;
                    let leaf_gen: u32;
                    {
                        let available = self.available_capacity();
                        if available < 2 {
                            error!("[INSERT] Not enough capacity for split (need 2 slots, have={}).", available);
                            return Err(Error::CapacityExceeded);
                        }
                        // Allocate internal node
                        if let Some(raw) = self.freelist.pop() {
                            let offset = (raw & 0xFFFF_FFFF) as u32;
                            debug!(
                                "[ALLOC] Reusing freed node for internal at offset={}",
                                offset
                            );
                            let node_ptr =
                                unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                            let gen = unsafe {
                                (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1
                            };
                            unsafe {
                                core::ptr::write_volatile(
                                    &mut (*node_ptr).key,
                                    stored_key & mask(split_bit),
                                );
                                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, split_bit);
                                (*node_ptr).is_terminal.store(0, Ordering::Relaxed); // internal nodes are not terminal
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
                                core::ptr::write_volatile(
                                    &mut (*node_ptr).key,
                                    stored_key & mask(split_bit),
                                );
                                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, split_bit);
                                (*node_ptr).generation.store(1, Ordering::Relaxed);
                                (*node_ptr).left.store(0, Ordering::Relaxed);
                                (*node_ptr).right.store(0, Ordering::Relaxed);
                                (*node_ptr).expires.store(u64::MAX, Ordering::Relaxed);
                                (*node_ptr).is_terminal.store(0, Ordering::Relaxed);
                                // internal nodes are not terminal
                            }
                            internal_gen = 1;
                        }
                        // Allocate leaf node
                        if let Some(raw) = self.freelist.pop() {
                            let offset = (raw & 0xFFFF_FFFF) as u32;
                            debug!("[ALLOC] Reusing freed node for leaf at offset={}", offset);
                            let node_ptr =
                                unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                            let gen = unsafe {
                                (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1
                            };
                            unsafe {
                                core::ptr::write_volatile(&mut (*node_ptr).key, stored_key);
                                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                                (*node_ptr).left.store(0, Ordering::Relaxed);
                                (*node_ptr).right.store(0, Ordering::Relaxed);
                                (*node_ptr).expires.store(expires, Ordering::Relaxed);
                                (*node_ptr).is_terminal.store(1, Ordering::Relaxed); // ← NEW: mark leaf as terminal
                                (*node_ptr).refcnt.store(1, Ordering::Relaxed); // first occurrence
                            }
                            leaf_offset = offset;
                            leaf_gen = gen;
                        } else {
                            let index = hdr.next_index.fetch_add(1, Ordering::Relaxed);
                            if (index as usize) >= hdr.capacity {
                                hdr.next_index.fetch_sub(1, Ordering::Relaxed);
                                let internal_index = ((internal_offset as usize)
                                    - size_of::<Header>())
                                    / size_of::<Node>();
                                if internal_index == (index as usize) - 1 {
                                    // Retire the internal_offset using epoch-based reclamation
                                    let off = internal_offset;
                                    // No free_slots update needed here, as this is a failed allocation rollback
                                    self.retire_offset(off);
                                }
                                return Err(Error::CapacityExceeded);
                            }
                            leaf_offset = HEADER_PADDED as Offset
                                + (index as Offset) * size_of::<Node>() as Offset;
                            let node_ptr = unsafe {
                                self.base.as_ptr().add(leaf_offset as usize) as *mut Node
                            };
                            unsafe {
                                core::ptr::write_volatile(&mut (*node_ptr).key, stored_key);
                                core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                                (*node_ptr).generation.store(1, Ordering::Relaxed);
                                (*node_ptr).left.store(0, Ordering::Relaxed);
                                (*node_ptr).right.store(0, Ordering::Relaxed);
                                (*node_ptr).expires.store(expires, Ordering::Relaxed);
                                (*node_ptr).is_terminal.store(1, Ordering::Relaxed); // ← NEW: mark leaf as terminal
                                (*node_ptr).refcnt.store(1, Ordering::Relaxed); // first occurrence
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
                        debug!(
                            "[INSERT] Linking new internal node at offset={}.",
                            internal_offset
                        );

                        // Atomically update the parent link to point to the new internal node
                        let link_atomic = &*(current_link_ptr as *const AtomicU64);
                        if link_atomic
                            .compare_exchange(
                                current_ptr,
                                pack(internal_offset, internal_gen),
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_err()
                        {
                            warn!("[INSERT] Split CAS failed. Recycling nodes and restarting.");
                            // Retire both offsets using epoch-based reclamation
                            let int_off = internal_offset;
                            let leaf_off = leaf_offset;
                            // Workaround: store offset of free_slots field from base pointer, reconstruct in closure
                            let base_addr = self.hdr.as_ptr() as usize;
                            let free_slots_offset =
                                (&(*self.hdr.as_ptr()).free_slots as *const AtomicU32 as usize)
                                    - base_addr;
                            self.retire_offset(int_off);
                            self.retire_offset(leaf_off);
                            // counter and queue stay consistent
                            let free_slots_ptr =
                                (base_addr + free_slots_offset) as *const AtomicU32;
                            (*free_slots_ptr).fetch_add(2, Ordering::Release);
                            continue;
                        }
                    }
                    debug!("[INSERT] Finished Subcase 2c (split).");
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
                let next_bit = get_bit(stored_key, current_node.prefix_len);
                let child_atomic = if next_bit == 0 {
                    &current_node.left
                } else {
                    &current_node.right
                };

                let child_ptr = child_atomic.load(Ordering::Acquire);

                if child_ptr == 0 {
                    // Child missing → insert leaf *here*
                    let (leaf_off, leaf_gen, _) =
                        self.alloc_node(stored_key, prefix_len, expires, tag)?;
                    child_atomic.store(pack(leaf_off, leaf_gen), Ordering::Release);
                    debug!(
                        "[INSERT] Inserted new leaf at offset={}, gen={}",
                        leaf_off,
                        leaf_gen
                    );
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
    fn allocate_node_with_gen(
        &self,
        key: u128,
        prefix_len: u8,
        expires: u64,
    ) -> Result<(Offset, u32), Error> {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let hdr_size = HEADER_PADDED as Offset;
        let node_size = size_of::<Node>() as Offset;
        loop {
            // ① Try to reuse a freed slot first (cheap fast-path)
            if let Some(raw) = self.freelist.pop() {
                let offset = (raw & 0xFFFF_FFFF) as u32;
                hdr.free_slots.fetch_sub(1, Ordering::Release);
                let node_ptr = unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                let gen = unsafe {
                    let g = (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1;
                    core::ptr::write_volatile(&mut (*node_ptr).key, key);
                    core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                    (*node_ptr).is_terminal.store(1, Ordering::Relaxed); // new leaves are stored prefixes
                    (*node_ptr).refcnt.store(1, Ordering::Relaxed); // first occurrence
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
                    (*node_ptr).is_terminal.store(1, Ordering::Relaxed); // new leaves are stored prefixes
                    (*node_ptr).refcnt.store(1, Ordering::Relaxed); // first occurrence
                    (*node_ptr).left.store(0, Ordering::Relaxed);
                    (*node_ptr).right.store(0, Ordering::Relaxed);
                    (*node_ptr).expires.store(expires, Ordering::Relaxed);
                }
                return Ok((offset, 1));
            }
            // === PATCH 4: Race-free next_index rollback (CAS loop) ===
            // ─── PATCH 4: only the thread that over‑allocated rolls back ───
            loop {
                let cur = hdr.next_index.load(Ordering::SeqCst);
                if cur == 0 {
                    break;
                }
                if hdr
                    .next_index
                    .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    break;
                }
            }

            // ③ Arena full – try once to flush deferred frees
            if hdr.free_slots.load(Ordering::Acquire) == 0 {
                return Err(Error::CapacityExceeded);
            }
            epoch::pin().flush();
            if let Some(raw) = self.freelist.pop() {
                let offset = (raw & 0xFFFF_FFFF) as u32;
                hdr.free_slots.fetch_sub(1, Ordering::Release);
                let node_ptr = unsafe { self.base.as_ptr().add(offset as usize) as *mut Node };
                let gen = unsafe {
                    let g = (*node_ptr).generation.fetch_add(1, Ordering::Relaxed) + 1;
                    core::ptr::write_volatile(&mut (*node_ptr).key, key);
                    core::ptr::write_volatile(&mut (*node_ptr).prefix_len, prefix_len);
                    (*node_ptr).left.store(0, Ordering::Relaxed);
                    (*node_ptr).right.store(0, Ordering::Relaxed);
                    (*node_ptr).expires.store(expires, Ordering::Relaxed);
                    (*node_ptr).refcnt.store(1, Ordering::Relaxed); // first occurrence
                    g
                };
                return Ok((offset, gen));
            } else {
                return Err(Error::CapacityExceeded); // caller will drop lock and retry
            }
        }
    }

    /// Allocates a node and optionally copies a tag (≤ TAG_MAX_LEN).
    /// Returns (node_offset, generation, tag_index).
    pub fn alloc_node(
        &self,
        key: u128,
        plen: u8,
        ttl: u64,
        tag: Option<&str>,
    ) -> Result<(Offset, u32, u32), Error> {
        if let Some(s) = tag {
            if s.len() > TAG_MAX_LEN {
                return Err(Error::TagTooLong);
            }
        }
        let (off, gen) = self.allocate_node_with_gen(key, plen, ttl)?;
        let idx = (off - HEADER_PADDED as u32) / size_of::<Node>() as u32;
        // Only write into the slab if we actually have a tag
        if let Some(s) = tag {
            unsafe {
                let dst = self.tag_base.as_ptr().add(idx as usize * TAG_MAX_LEN) as *mut u8;
                core::ptr::write_bytes(dst, 0, TAG_MAX_LEN);
                core::ptr::copy_nonoverlapping(s.as_ptr(), dst, s.len());
            }
        }
        let node = unsafe { &*(self.base.as_ptr().add(off as usize) as *const Node) };
        node.tag_off.store(idx, Ordering::Release);
        Ok((off, gen, idx))
    }

    #[inline(always)]
    fn follow(&self, packed: u64) -> Option<(&Node, u32)> {
        if packed == 0 {
            return None;
        }
        let (off, gen) = unpack(packed);
        let ptr = unsafe { self.base.as_ptr().add(off as usize) as *const Node };
        Some((unsafe { &*ptr }, gen))
    }

    /// If `parent_link` now points to a node with exactly one live child,
    /// graft that child into the parent, recycle the old node.
    fn try_prune(&self, parent_link: &AtomicU64, parent_plen: u8) {
        let packed = parent_link.load(Ordering::Acquire);
        let (off, _) = unpack(packed);
        if off == 0 {
            return;
        }
        // SAFETY: off points at a valid Node
        let node = unsafe { &*(self.base.as_ptr().add(off as usize) as *const Node) };
        // If this node still represents a stored prefix, it must stay,
        // even if it has only one live child.
        if node.is_terminal.load(Ordering::Acquire) == 1 && node.refcnt.load(Ordering::Acquire) > 0
        {
            return; // keep: cannot prune a terminal node
        }
        let left = node.left.load(Ordering::Acquire);
        let right = node.right.load(Ordering::Acquire);
        // only prune unary nodes (one child zero, one nonzero)
        let (child, which_side) = match (left, right) {
            (0, r) if r != 0 => (r, 1),
            (l, 0) if l != 0 => (l, 0),
            _ => return,
        };

        // keep the tree sound: the child must *really* live on that side
        let (coff, _) = unpack(child);
        let cnode = unsafe { &*(self.base.as_ptr().add(coff as usize) as *const Node) };
        if get_bit(cnode.key, parent_plen) != which_side {
            return; // side mismatch – don’t prune
        }

        // swap in the single child
        parent_link.store(child, Ordering::Release);
        // retire the old node offset
        let off_u32 = off as Offset;
        let hdr_ref = unsafe { &*self.hdr.as_ptr() };
        hdr_ref.free_slots.fetch_add(1, Ordering::Release);
        self.retire_offset(off_u32);
    }

    /// Lookup a key and return detailed match information if found and not expired.
    pub fn lookup(&self, key: u128) -> Option<Match<'_>> {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        let mut link = hdr.root_offset.load(Ordering::Acquire);
        let mut parent_link = &hdr.root_offset as *const AtomicU64; // track parent
        let mut parent_plen = 0u8;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX_EPOCH in lookup; system clock is invalid")
            .as_secs();
        while link != 0 {
            let (node, gen) = match self.follow(link) {
                Some((n, g)) => (n, g),
                None => break,
            };
            if gen != node.generation.load(Ordering::Acquire) {
                // ABA detected: retry from root
                link = hdr.root_offset.load(Ordering::Acquire);
                continue;
            }
            // -------- opportunistic prune on the *node we just left* ----------
            // Parent plen is the prefix length we used to decide the branch.
            self.try_prune(unsafe { &*parent_link }, parent_plen);

            // Work with the masked (canonical) value for CPL and equality
            let canon = canonical(key, node.prefix_len);
            let cpl = common_prefix_len(canon, node.key, node.prefix_len);
            if cpl < node.prefix_len {
                return None;
            }

            let exp = node.expires.load(Ordering::Acquire);
            if cpl == node.prefix_len {
                // Return if this node was explicitly stored (leaf or internal)
                if node.is_terminal.load(Ordering::Acquire) == 1
                    && node.refcnt.load(Ordering::Acquire) > 0
                    && canon == node.key
                {
                    // opportunistic GC of dead leaves ───
                    if exp != u64::MAX && exp < now {
                        if let Some(_g) = unsafe {
                            hdr.lock
                                .assume_init_ref()
                                .try_write_lock(Timeout::Val(Duration::from_secs(0)))
                        } {
                            // double‑check under lock
                            if node.expires.load(Ordering::Acquire) < now {
                                node.is_terminal.store(0, Ordering::Release);
                                node.refcnt.store(0, Ordering::Release);
                                hdr.free_slots.fetch_add(1, Ordering::Release);
                                let off = (node as *const _ as usize - self.base.as_ptr() as usize)
                                    as Offset;
                                self.retire_offset(off);
                            }
                        }
                        link = hdr.root_offset.load(Ordering::Acquire);
                        continue;
                    }
                    // Return the match info
                    let idx = node.tag_off.load(Ordering::Acquire);
                    unsafe {
                        let ptr = self.tag_base.as_ptr().add(idx as usize * TAG_MAX_LEN);
                        let slice = std::slice::from_raw_parts(ptr, TAG_MAX_LEN);
                        let mut len = TAG_MAX_LEN;
                        while len > 0 && slice[len - 1] == 0 {
                            len -= 1;
                        }
                        let tag = core::str::from_utf8_unchecked(&slice[..len]);
                        return Some(Match {
                            cidr_key: node.key,
                            plen: node.prefix_len,
                            tag,
                        });
                    }
                }
                // else: internal node expired, but traversal continues
            }

            if node.prefix_len >= 128 {
                return None;
            }

            let next_bit = get_bit(key, node.prefix_len);
            let child_link = if next_bit == 0 {
                node.left.load(Ordering::Acquire)
            } else {
                node.right.load(Ordering::Acquire)
            };

            // ─── PATCH 2: detect ABA on the child itself ───
            if let Some((child_node, child_gen)) = self.follow(child_link) {
                if child_gen != child_node.generation.load(Ordering::Acquire) {
                    // Stale pointer – restart from root
                    link = hdr.root_offset.load(Ordering::Acquire);
                    continue;
                }
            }
            parent_plen = node.prefix_len;
            parent_link = if next_bit == 0 {
                &node.left as *const AtomicU64
            } else {
                &node.right as *const AtomicU64
            };

            link = child_link;
        }
        None
    }
    /// Delete a key with a given prefix length (expire immediately, concurrency-safe, only expires exact leaf nodes).
    /// Both `key` and `prefix_len` must match a leaf node for deletion to occur.
    pub fn delete(&self, key: u128, prefix_len: u8) -> Result<(), Error> {
        info!("[DELETE] key={:x}, prefix_len={}", key, prefix_len);
        let hdr = unsafe { &*self.hdr.as_ptr() };
        // Acquire write lock using guard
        let _write_guard = unsafe {
            hdr.lock.assume_init_ref().write_lock()
                .map_err(|e| Error::Lock(format!("write_lock failed: {e}")))?
        };
        debug!("[DELETE] Lock acquired.");

        // Store canonical key
        let stored_key = canonical(key, prefix_len);

        // Track parent links for pruning
        let mut links: Vec<(&AtomicU64, u8)> = Vec::with_capacity(128);
        links.push((&hdr.root_offset, 0)); // root has fictitious plen 0
        let mut current_ptr = hdr.root_offset.load(Ordering::Relaxed);
        let mut current_offset;
        let mut current_gen;
        (current_offset, current_gen) = unpack(current_ptr);
        debug!(
            "[DELETE] Starting at root_offset={}, gen={}",
            current_offset, current_gen
        );

        while current_offset != 0 {
            trace!("[DELETE] Loop: current_offset={}", current_offset);
            let node_ptr = unsafe { self.base.as_ptr().add(current_offset as usize) as *mut Node };
            let node = unsafe { &*node_ptr }; // Read-only ref first
            let node_gen = node.generation.load(Ordering::Acquire);
            if node_gen != current_gen {
                // ABA detected, restart from root
                links.clear();
                links.push((&(*hdr).root_offset, 0));
                current_ptr = hdr.root_offset.load(Ordering::Relaxed);
                (current_offset, current_gen) = unpack(current_ptr);
                continue;
            }
            debug!(
                "[DELETE] Node: key={:x}, prefix_len={}, gen={}",
                node.key, node.prefix_len, node_gen
            );

            // Compare the canonical key against the node's key up to the node's prefix length.
            let cpl = common_prefix_len(stored_key, node.key, node.prefix_len);
            trace!("[DELETE] cpl={}", cpl);

            if cpl < node.prefix_len {
                debug!("[DELETE] Diverged (cpl < node.prefix_len). Key not found.");
                return Ok(()); // Key not found in this subtree
            }

            // Unmark the stored-prefix flag first (masked)
            if cpl == node.prefix_len && node.key == stored_key && node.prefix_len == prefix_len {
                if node.refcnt.fetch_sub(1, Ordering::AcqRel) == 1 {
                    // last stored copy vanished
                    let left = node.left.load(Ordering::Acquire);
                    let right = node.right.load(Ordering::Acquire);

                    if left == 0 && right == 0 {
                        // real leaf → safe to unlink and recycle
                        if let Some(&(plink, _)) = links.last() {
                            plink.store(0, Ordering::Release);
                        }
                        node.is_terminal.store(0, Ordering::Release);
                        let off = current_offset as Offset;
                        hdr.free_slots.fetch_add(1, Ordering::Release);
                        self.retire_offset(off);
                    } else {
                        // still has children → keep node, just clear flag
                        node.is_terminal.store(0, Ordering::Release);
                    }

                    // ancestors may now be unary – give prune a chance
                    for &(link, plen) in links.iter().rev() {
                        self.try_prune(link, plen);
                    }
                    info!("[DELETE] Node cleared (or recycled) and prune pass done.");
                    return Ok(());
                } else {
                    // Already un-marked: idempotent no-op
                    debug!("[DELETE] Node was already not terminal. No-op.");
                    return Ok(());
                }
            }
            // If keys don't match exactly, or the prefix length does not match, continue searching deeper.
            trace!("[DELETE] Prefix matches, but key or prefix_len differs or not a leaf. Traversing down.");

            if node.prefix_len >= 128 {
                #[cfg(debug_assertions)]
                trace!(
                    "[DELETE] Node prefix_len >= 128, but key didn't match exactly. Key not found."
                );
                return Ok(()); // Cannot go deeper
            }

            let next_bit = get_bit(stored_key, node.prefix_len);
            trace!(
                "[DELETE] Traversing based on bit {} = {}",
                node.prefix_len,
                next_bit
            );
            let child_atomic = if next_bit == 0 {
                &node.left
            } else {
                &node.right
            };
            current_ptr = child_atomic.load(Ordering::Relaxed);
            links.push((child_atomic, node.prefix_len));
            (current_offset, current_gen) = unpack(current_ptr);
        }
        debug!("[DELETE] Reached end of branch (offset 0). Key not found.");
        self.cleanup_root();
        Ok(())
    }

    /// Bulk insert multiple entries
    pub fn bulk_insert(&self, items: &[(u128, u8, u64)]) -> Result<(), Error> {
        for &(k, l, t) in items {
            self.insert(k, l, t, None)?;
        }
        Ok(())
    }

    /// Clears the entire tree (drops all nodes).
    pub fn clear(&self) -> Result<(), Error> {
        info!("[CLEAR] Clearing tree.");
        let hdr = unsafe { &*self.hdr.as_ptr() };
        // Acquire write lock using guard
        let _write_guard = unsafe {
            hdr.lock.assume_init_ref().write_lock()
                .map_err(|e| Error::Lock(format!("write_lock failed: {e}")))?
        };
        debug!("[CLEAR] Lock acquired.");

        // walk arena, push all used offsets into freelist
        for i in 0..hdr.next_index.load(Ordering::Acquire) {
            let off = HEADER_PADDED as Offset + i * size_of::<Node>() as Offset;
            self.retire_offset(off);
        }
        hdr.free_slots.store(
            hdr.next_index.swap(0, Ordering::Release),
            Ordering::Release,
        );
        hdr.root_offset.store(0, Ordering::Release);

        info!("[CLEAR] Tree cleared.");
        // Remove explicit unlock, guard will handle it
        // hdr.lock.write_unlock();
        Ok(())
    }
    /// If the current root is a non‑terminal node with only one child,
    /// promote that child (repeat until this is no longer true).
    fn cleanup_root(&self) {
        loop {
            // 1) load packed pointer
            let packed = unsafe { &*self.hdr.as_ptr() }
                .root_offset
                .load(Ordering::Acquire);
            if packed == 0 {
                return;
            }

            // 2) unpack it **before dereferencing**
            let (off, _) = unpack(packed);
            let root = self.node(off as u64);

            if root.is_terminal.load(Ordering::Relaxed) != 0 {
                return;
            }

            let left = root.left.load(Ordering::Acquire);
            let right = root.right.load(Ordering::Acquire);

            let only = match (left, right) {
                (0, 0) => return,
                (l, 0) => l,
                (0, r) => r,
                _ => return, // two children, keep the node
            };

            // 3) promote the single child – keep it *packed*
            unsafe { &*self.hdr.as_ptr() }
                .root_offset
                .store(only, Ordering::Release);

            // 4) recycle the old root – pass the real offset
            self.free_node(off as u64);

            // maybe collapse another level
        }
    }

    /// Helper to get a mutable reference to a node by offset
    fn node(&self, offset: u64) -> &Node {
        unsafe { &*(self.base.as_ptr().add(offset as usize) as *const Node) }
    }

    /// Helper to recycle a node by offset
    fn free_node(&self, offset: u64) {
        let off = offset as Offset;
        let hdr = unsafe { &*self.hdr.as_ptr() };
        hdr.free_slots.fetch_add(1, Ordering::Release);
        self.retire_offset(off);
    }
    /// Explicitly destroy the shared memory segment and unlink it.
    /// After calling this, the handle must not be used again.
    pub fn destroy(self) {
        // Drop will run, which will call platform_drop and unmap the segment.
        // This method exists for explicitness in FFI.
        // No-op body: Drop does the work.
    }
    /// Grow the arena *in place*.  All threads in this process keep using the
    /// same `PatriciaTree` handle; other processes reopen when convenient.
    /// Blocks writers via the global RW‑lock while copying.
    pub fn resize(&mut self, new_capacity: usize) -> Result<(), Error> {
        let hdr = unsafe { &*self.hdr.as_ptr() };
        if new_capacity <= hdr.capacity {
            return Err(Error::InvalidPrefix); // “too small”
        }

        // ---- exclusive lock: no mutators, look‑ups keep running ----------
        let _guard = unsafe {
            hdr.lock.assume_init_ref().write_lock()
                .map_err(|e| Error::Lock(format!("write_lock failed: {e}")))?
        };

        // ---- build a bigger mapping next to the old one -------------------
        let next_name = format!("{}_next{}", self.os_id, std::process::id());
        let mut next =
            PatriciaTree::open(&next_name, new_capacity).map_err(|_| Error::CapacityExceeded)?;

        // ---- DFS copy live prefixes --------------------------------------
        let mut stack = Vec::with_capacity(64);
        let root = hdr.root_offset.load(Ordering::Acquire);
        if root != 0 {
            stack.push(root);
        }
        while let Some(packed) = stack.pop() {
            let (off, _) = unpack(packed);
            let node = self.node(off as u64);
            if node.is_terminal.load(Ordering::Acquire) == 1
                && node.refcnt.load(Ordering::Acquire) > 0
            {
                let ttl = node.expires.load(Ordering::Acquire).saturating_sub(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("SystemTime before UNIX_EPOCH in resize; system clock is invalid")
                        .as_secs(),
                );
                next.insert(node.key, node.prefix_len, ttl, None)?;
            }
            let l = node.left.load(Ordering::Acquire);
            let r = node.right.load(Ordering::Acquire);
            if l != 0 {
                stack.push(l);
            }
            if r != 0 {
                stack.push(r);
            }
        }

        // ---- swap internal handles ---------------------------------------
        // SAFETY: we hold the write‑lock, so no other thread can access
        // `self` mutably while the swap happens.
        unsafe {
            std::ptr::swap(&mut self.shmem, &mut next.shmem);
            std::ptr::swap(&mut self.base, &mut next.base);
            std::ptr::swap(&mut self.hdr, &mut next.hdr);
            std::ptr::swap(&mut self.os_id, &mut next.os_id);
        }
        // `next` now owns the *old* mapping and will unmap it on drop.
        Ok(())
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
                crate::platform::unix::platform_drop(&self.os_id);
            }
            #[cfg(target_os = "windows")]
            {
                crate::platform::windows::platform_drop(&self.os_id);
            }
        }
        // The mapping itself is unmapped automatically by Shmem’s Drop
    }
}
