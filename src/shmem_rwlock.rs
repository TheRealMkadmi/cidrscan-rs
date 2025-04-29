//! Cross-process read–write lock that fits in shared memory and
//! works on Linux, macOS and Windows.
//! Implements writer preference to avoid starvation.
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use raw_sync::events::{Event as RawEvent, EventImpl, EventInit};
use raw_sync::locks::{LockImpl, LockInit, Mutex as RawMutex};
use raw_sync::Timeout;
// Stable allocation imports for boxed helper
use std::alloc::{alloc_zeroed, handle_alloc_error, Layout};
use once_cell::sync::OnceCell;             // NEW

const MUTEX_BUF_SIZE: usize = core::mem::size_of::<RawMutex>();
const EVENT_BUF_SIZE: usize = core::mem::size_of::<RawEvent>();
const _: () = {
    assert!(core::mem::size_of::<RawRwLock>() % core::mem::align_of::<RawRwLock>() == 0);
};

/// Our shared-memory lock layout: [mutex-bytes][event-bytes][reader_count]
#[repr(C, align(8))]
pub struct RawRwLock {
    /// writer-gate storage buffer
    mutex_buf: [u8; MUTEX_BUF_SIZE],
    /// event storage buffer
    event_buf: [u8; EVENT_BUF_SIZE],
    /// number of readers (low 31 bits), high bit is "writer present" flag
    pub readers: AtomicU32,
    // NOT in shared-mem logic – just per-process caches
    mutex_impl: OnceCell<Box<dyn LockImpl>>,
    event_impl: OnceCell<Box<dyn EventImpl>>,
}

// SAFETY: The underlying primitives from raw_sync are designed for cross-process
// and potentially cross-thread use, even though they contain raw pointers.
// Marking RawRwLock as Send + Sync is safe for use cases like the tests
// where it's managed within a single process (e.g., via Arc).
unsafe impl Send for RawRwLock {}
unsafe impl Sync for RawRwLock {}

impl RawRwLock {
    #[inline(always)]
    fn mutex<'a>(&'a self) -> &'a dyn LockImpl {
        self.mutex_impl.get().expect("RawRwLock not initialised").as_ref()
    }

    #[inline(always)]
    /// creator = true for brand-new mapping, false for reopen
    unsafe fn init_handles(&self, creator: bool) -> Result<(), Box<dyn std::error::Error>> {
        if creator {
            let (m_raw, _) = RawMutex::new(self.mutex_ptr(), ptr::null_mut())?;
            let m: Box<dyn LockImpl> = m_raw;
            let (e_raw, _) = RawEvent::new(self.event_ptr(), true)?;
            let e: Box<dyn EventImpl> = e_raw;
            self.mutex_impl.set(m);
            self.event_impl.set(e);
        } else {
            let (m_raw, _) = RawMutex::from_existing(self.mutex_ptr(), ptr::null_mut())?;
            let m: Box<dyn LockImpl> = m_raw;
            let (e_raw, _) = RawEvent::from_existing(self.event_ptr())?;
            let e: Box<dyn EventImpl> = e_raw;
            self.mutex_impl.set(m);
            self.event_impl.set(e);
        }
        Ok(())
    }

    #[inline(always)]
    fn event(&self) -> &dyn EventImpl {
        self.event_impl.get().expect("RawRwLock not initialised").as_ref()
    }
    /// Helper to get a mutable pointer to the mutex buffer.
    #[inline(always)]
    fn mutex_ptr(&self) -> *mut u8 {
        // Cast self to a raw pointer to get the address of the buffer.
        // This is safe because the layout is repr(C).
        // Need to cast self to a mutable pointer first for RawMutex operations.
        ptr::addr_of!(self.mutex_buf) as *mut u8
    }

    /// Helper to get a mutable pointer to the event buffer.
    #[inline(always)]
    fn event_ptr(&self) -> *mut u8 {
        // Cast self to a raw pointer to get the address of the buffer.
        ptr::addr_of!(self.event_buf) as *mut u8
    }

    /// Initialize the lock structure in-place using field addresses.
    /// Returns Ok(()) on success, or an Error if initialization fails.
    ///
    /// Safety: ptr must be valid for writes, properly aligned (align(8)),
    /// and point to zeroed memory.
    pub unsafe fn new_in_place(ptr: *mut RawRwLock) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure the provided pointer is not null
        if ptr.is_null() {
            return Err("Null pointer passed to new_in_place".into());
        }
        // Ensure the pointer is properly aligned for RawRwLock
        if (ptr as usize) % core::mem::align_of::<RawRwLock>() != 0 {
            return Err("RawRwLock pointer is not properly aligned".into());
        }

        // Get pointers to the start of the buffers within the pointed-to struct
        let mutex_ptr = ptr::addr_of_mut!((*ptr).mutex_buf) as *mut u8;
        let event_ptr = ptr::addr_of_mut!((*ptr).event_buf) as *mut u8;
        let readers_ptr = ptr::addr_of_mut!((*ptr).readers);

        // Check if buffer sizes are sufficient (optional, for debugging)
        // assert!(MUTEX_BUF_SIZE >= RawMutex::size_of(None));
        // assert!(EVENT_BUF_SIZE >= RawEvent::size_of(None));

        // Initialize mutex in its buffer
        // IMPORTANT: We must keep the Box<dyn LockImpl> alive, or the OS object is destroyed!
        // See: https://docs.rs/raw_sync/latest/raw_sync/locks/struct.Mutex.html
        // Create OS objects _and_ cache them for this process
        let this = &*ptr;
        this.init_handles(true)?;

        // Initialize readers field directly
        readers_ptr.write(AtomicU32::new(0));

        Ok(()) // Indicate success
    }

    /// Initialize the lock structure from a raw byte pointer.
    /// This is intended for initialization within a larger struct like Header.
    ///
    /// Safety: ptr must point to the beginning of a memory region
    /// suitable for a RawRwLock, be valid for writes, properly aligned (align(8)),
    /// and point to zeroed memory. The timeout parameter is currently ignored
    /// but kept for potential future compatibility or API consistency.
    pub unsafe fn init(ptr: *mut u8, _timeout: Timeout) -> Result<(), Box<dyn std::error::Error>> {
        // Cast the byte pointer to the specific lock type pointer.
        // This assumes the caller provides the correct starting address.
        let lock_ptr = ptr as *mut RawRwLock;
        // Call the in-place initializer.
        // Assuming the caller zeroed the memory.
        Self::new_in_place(lock_ptr)
    }

    /// Re-open an existing lock in shared memory using field addresses.
    /// Returns Ok(()) on success, or an Error if reopening fails.
    ///
    /// Safety: ptr must point at a properly initialized RawRwLock.
    pub unsafe fn reopen_in_place(ptr: *mut RawRwLock) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure the provided pointer is not null
        if ptr.is_null() {
            return Err("Null pointer passed to reopen_in_place".into());
        }
        // Get pointers to the start of the buffers within the pointed-to struct
        let mutex_ptr = ptr::addr_of_mut!((*ptr).mutex_buf) as *mut u8;
        let event_ptr = ptr::addr_of_mut!((*ptr).event_buf) as *mut u8;

        // Reopen mutex in its buffer
        (&*ptr).init_handles(false)?;
        Ok(()) // Indicate success
    }
    // Readers field state is preserved.
    /// Allocate and initialize a RawRwLock on the heap with correct alignment.
    /// Returns a boxed, zero-initialized, and fully constructed RawRwLock.
    pub fn boxed() -> Box<RawRwLock> {
        let layout = Layout::new::<RawRwLock>();
        unsafe {
            let ptr = alloc_zeroed(layout) as *mut RawRwLock;
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            RawRwLock::new_in_place(ptr).unwrap();
            Box::from_raw(ptr)
        }
    }
}
/// Represents an acquired exclusive (write) lock.
/// The lock is released when this guard is dropped.
#[must_use = "if unused the lock will immediately unlock"]
pub struct WriteGuard<'a> {
    lock: &'a RawRwLock,
    _guard: raw_sync::locks::LockGuard<'a>,
}

impl<'a> Drop for WriteGuard<'a> {
    fn drop(&mut self) {
        // allow readers again (writer flag → 0, counter already 0)
        self.lock.readers.store(0, Ordering::Release);
        // wake up any blocked readers
        self.lock.event().set(raw_sync::events::EventState::Signaled).unwrap();
        // _guard drop here → OS mutex unlocked by LockGuard drop
    }
}

/// Represents an acquired shared (read) lock.
/// The lock is released when this guard is dropped.
#[must_use = "if unused the lock will immediately unlock"]
pub struct ReadGuard<'a> {
    lock: &'a RawRwLock,
}

impl<'a> Drop for ReadGuard<'a> {
    fn drop(&mut self) {
        self.lock.read_unlock();
    }
}

const WRITER_BIT: u32 = 0x8000_0000;
const READER_MASK: u32 = WRITER_BIT - 1; // 0x7FFF_FFFF

impl RawRwLock {
    /// Acquire a **shared** (read) lock.
    /// Spins only if a writer holds the lock or is waiting.
    /// Returns a guard that releases the lock when dropped.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        loop {
            let current_readers = self.readers.load(Ordering::Relaxed);
            // If a writer holds the lock (flag set), spin.
            if current_readers & WRITER_BIT != 0 {
                core::hint::spin_loop();
                continue;
            }
            // Attempt to increment the reader count.
            match self.readers.compare_exchange_weak(
                current_readers,
                current_readers.wrapping_add(1), // Use wrapping_add for safety
                Ordering::Acquire, // Acquire barrier ensures subsequent reads see writer's changes
                Ordering::Relaxed, // Relaxed on failure is fine
            ) {
                Ok(_) => return ReadGuard { lock: self }, // Success, return guard
                Err(_) => continue,                       // CAS failed, retry loop
            }
        }
    }

    /// Release a shared (read) lock.
    /// Called automatically when ReadGuard is dropped.
    #[inline(never)] // Keep distinct from other methods for clarity
    fn read_unlock(&self) {
        let prev = self.readers.fetch_sub(1, Ordering::Release);
        // Only one pattern means “I was the last reader *and* a writer waits”:
        if prev == (WRITER_BIT | 1) {
            let _ = unsafe { RawEvent::from_existing(self.event_ptr()) }
                .and_then(|(ev, _)| ev.set(raw_sync::events::EventState::Signaled));
        }
    }

    /// Acquire an **exclusive** (write) lock.
    /// Blocks new readers and waits for in-flight readers to drain.
    /// Returns a guard that releases the lock when dropped.
    pub fn write_lock(&self) -> WriteGuard<'_> {
        // Acquire OS mutex using cached handle
        let guard = self.mutex().lock().expect("mutex lock failed");

        // 1. advertise writer *first*
        let prev = self.readers.fetch_or(WRITER_BIT, Ordering::AcqRel) & READER_MASK;

        // 2. now clear the manual-reset event
        self.event().set(raw_sync::events::EventState::Clear).unwrap();

        // 3) wait until the last reader wakes us
        if prev != 0 {
            self.event().wait(Timeout::Infinite).unwrap();
            // defensive: spin until the reader count really reached 0
            while self.readers.load(Ordering::Acquire) != WRITER_BIT {
                core::hint::spin_loop();
            }
        }
        WriteGuard {
            lock: self,
            _guard: guard,
        }
    }

    /// Try to acquire an **exclusive** (write) lock without blocking indefinitely.
    /// Returns Some(WriteGuard) if the lock was acquired, None otherwise.
    pub fn try_write_lock(&self, timeout: Timeout) -> Option<WriteGuard<'_>> {
        // Acquire OS mutex using cached handle
        let guard = self.mutex().try_lock(timeout).ok()?;
        // Try to block new readers
        if self
            .readers
            .compare_exchange(0, WRITER_BIT, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            drop(guard);
            return None;
        }
        Some(WriteGuard {
            lock: self,
            _guard: guard,
        })
    }
}
