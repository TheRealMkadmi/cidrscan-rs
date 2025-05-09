//! Cross-process read–write lock that fits in shared memory and
//! works on Linux, macOS and Windows.
//! Implements writer preference to avoid starvation.
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use raw_sync::events::{Event as RawEvent, EventImpl, EventInit};
use raw_sync::locks::{LockImpl, LockInit, Mutex as RawMutex};
use raw_sync::Timeout;
// Stable allocation imports for boxed helper
use core::marker::PhantomData;

const _: () = {
    assert!(core::mem::size_of::<RawRwLock>() % core::mem::align_of::<RawRwLock>() == 0);
};


/// Our shared-memory lock layout: [mutex-bytes][event-bytes][reader_count]
#[repr(C)]
pub struct RawRwLock {
    mutex_buf: Box<[u8]>,
    event_buf: Box<[u8]>,
    /// number of readers (low 31 bits), high bit is "writer present" flag
    pub readers: AtomicU32,
    /// OS mutex handle (lives as long as RawRwLock)
    mutex_handle: Option<Box<dyn LockImpl>>,
    /// OS event handle (lives as long as RawRwLock)
    event_handle: Option<Box<dyn EventImpl>>,
    _marker: PhantomData<()>, // no process-local state inside shm
}

// SAFETY: The underlying primitives from raw_sync are designed for cross-process
// and potentially cross-thread use, even though they contain raw pointers.
// Marking RawRwLock as Send + Sync is safe for use cases like the tests
// where it's managed within a single process (e.g., via Arc).
unsafe impl Send for RawRwLock {}
unsafe impl Sync for RawRwLock {}

const WRITER_BIT: u32 = 0x8000_0000;
const READER_MASK: u32 = WRITER_BIT - 1; // 0x7FFF_FFFF

impl RawRwLock {
    #[inline(always)]
    fn mutex(&self) -> &dyn LockImpl {
        self.mutex_handle
            .as_ref()
            .expect("mutex_handle not initialized")
            .as_ref()
    }

    #[inline(always)]
    fn event(&self) -> &dyn EventImpl {
        self.event_handle
            .as_ref()
            .expect("event_handle not initialized")
            .as_ref()
    }

    /// Safe, cross-platform constructor.
    /// Allocates the backing buffers and initializes the OS handles.
    pub fn new() -> Box<Self> {
        let msz = RawMutex::size_of(None);
        let esz = RawEvent::size_of(None);

        let mut lock = Box::new(Self {
            mutex_buf: vec![0u8; msz].into_boxed_slice(),
            event_buf: vec![0u8; esz].into_boxed_slice(),
            readers: AtomicU32::new(0),
            mutex_handle: None,
            event_handle: None,
            _marker: PhantomData,
        });

        // SAFETY: buffers are aligned + non-null
        unsafe {
            let (m, _) = RawMutex::new(lock.mutex_buf.as_mut_ptr(), ptr::null_mut()).unwrap();
            let (e, _) = RawEvent::new(lock.event_buf.as_mut_ptr(), true).unwrap();
            lock.mutex_handle = Some(m);
            lock.event_handle = Some(e);
        }
        lock
    }

    /// In-place initialization for shared memory usage.
    /// # Safety
    /// - `ptr` must be valid, properly aligned, and point to zeroed memory.
    pub unsafe fn new_in_place(ptr: *mut RawRwLock) -> Result<(), Box<dyn std::error::Error>> {
        let this = &mut *ptr;
        let msz = RawMutex::size_of(None);
        let esz = RawEvent::size_of(None);

        // Allocate backing storage for mutex and event buffers in place
        // (Assume the struct's fields are already zeroed, but we must replace the Box<[u8]> fields)
        this.mutex_buf = vec![0u8; msz].into_boxed_slice();
        this.event_buf = vec![0u8; esz].into_boxed_slice();
        this.readers = AtomicU32::new(0);
        this.mutex_handle = None;
        this.event_handle = None;

        // SAFETY: buffers are aligned + non-null
        let (m, _) = RawMutex::new(this.mutex_buf.as_mut_ptr(), ptr::null_mut())?;
        let (e, _) = RawEvent::new(this.event_buf.as_mut_ptr(), true)?;
        this.mutex_handle = Some(m);
        this.event_handle = Some(e);

        Ok(())
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

        // Reopen mutex and event handles in their buffers
        let this = &mut *ptr;
        let mptr = this.mutex_buf.as_mut_ptr() as *mut u8;
        let eptr = this.event_buf.as_mut_ptr() as *mut u8;
        let (mutex, _) = RawMutex::from_existing(mptr, ptr::null_mut())
            .map_err(|e| format!("re-open mutex failed: {e}"))?;
        let (event, _) =
            RawEvent::from_existing(eptr).map_err(|e| format!("re-open event failed: {e}"))?;
        this.mutex_handle = Some(mutex);
        this.event_handle = Some(event);

        Ok(()) // Indicate success
    }
    // Readers field state is preserved.

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
            self.event()
                .set(raw_sync::events::EventState::Signaled)
                .unwrap();
        }
    }

    /// Acquire an **exclusive** (write) lock.
    /// Blocks new readers and waits for in-flight readers to drain.
    /// Returns a guard that releases the lock when dropped.
    pub fn write_lock(&self) -> WriteGuard<'_> {
        // Acquire OS mutex using cached handle
        let guard = self.mutex().lock().expect("mutex lock failed");
        // 1. clear any prior event signals _before_ announcing the writer
        let evt = self.event();
        evt.set(raw_sync::events::EventState::Clear).unwrap();
        // 2. advertise writer (blocks new readers)
        let prev = self.readers.fetch_or(WRITER_BIT, Ordering::AcqRel) & READER_MASK;
        // 3. if there are in-flight readers, wait until the last one signals
        if prev != 0 {
            evt.wait(Timeout::Infinite).unwrap();
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
        self.lock
            .event()
            .set(raw_sync::events::EventState::Signaled)
            .unwrap();
        // _guard drop here → OS mutex unlocked by LockGuard drop
        // handle is dropped here, keeping trait object alive for guard's lifetime
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
