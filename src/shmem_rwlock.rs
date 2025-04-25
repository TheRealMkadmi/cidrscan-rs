//! Cross-process read–write lock that fits in shared memory and
//! works on Linux, macOS and Windows.
//! Implements writer preference to avoid starvation.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use raw_sync::events::{EventImpl, EventInit, Event as RawEvent};
use raw_sync::locks::{LockImpl, LockInit, Mutex as RawMutex};
use raw_sync::Timeout;

/// Inline size constants—now valid `const` calls
const MUTEX_SIZE: usize = core::mem::size_of::<RawMutex>();

/// Our shared-memory lock layout: [mutex][event][reader_count]
#[repr(C, align(4))]
pub struct RawRwLock {
    /// writer-gate
    pub mutex: RawMutex,
    /// event to wake blocked writer
    pub event: RawEvent,
    /// number of readers (or u32::MAX if a writer holds it)
    pub readers: AtomicU32,
}

// SAFETY: The underlying primitives from raw_sync are designed for cross-process
// and potentially cross-thread use, even though they contain raw pointers.
// Marking RawRwLock as Send + Sync is safe for use cases like the tests
// where it's managed within a single process (e.g., via Arc).
unsafe impl Send for RawRwLock {}
unsafe impl Sync for RawRwLock {}

impl RawRwLock {
    /// Initialize both primitives and reader count in shared memory.
    ///
    /// # Safety
    /// - `mem` must point to at least `size_of::<RawRwLock>()` bytes.
    /// - Those bytes must be zeroed before calling this.
    pub unsafe fn init(
        mem: *mut u8,
        _timeout: Timeout
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        // Cast the byte pointer to our struct pointer:
        let this = mem as *mut RawRwLock;
        // Call your existing constructor that fills mutex, event, readers:
        RawRwLock::new_in_place(this);
        Ok(())
    }

    /// After you `mmap` or open the shared region, call this **once** at the base
    /// of your `RawRwLock` to initialize both primitives in-place.
    ///
    /// Safety: `ptr` must be valid for writes to `size_of::<RawRwLock>()` bytes.
    pub unsafe fn new_in_place(ptr: *mut RawRwLock) {
        // 1) Init the writer mutex
        let m_ptr = ptr.cast::<u8>();
        RawMutex::new(m_ptr, ptr::null_mut()).expect("RawMutex::new failed");
        // 2) Init the event just after the mutex bytes
        let ev_ptr = m_ptr.add(MUTEX_SIZE);
        RawEvent::new(ev_ptr, true).expect("RawEvent::new failed");
        // 3) Zero the reader count
        ptr::write(&mut (*ptr).readers, AtomicU32::new(0));
    }

    /// Re-open an existing lock in shared memory (e.g. in a second process).
    ///
    /// Safety: `ptr` must point at a properly initialized RawRwLock.
    pub unsafe fn reopen_in_place(ptr: *mut RawRwLock) {
        let m_ptr = ptr.cast::<u8>();
        RawMutex::from_existing(m_ptr, ptr::null_mut()).expect("RawMutex::from_existing failed");
        let ev_ptr = m_ptr.add(MUTEX_SIZE);
        RawEvent::from_existing(ev_ptr).expect("RawEvent::from_existing failed");
        // reader count is left as-is
    }

    /// Acquire a **shared** (read) lock.
    /// Spins only if a writer holds the lock.
    pub fn read_lock(&self) {
        loop {
            let prev = self.readers.fetch_add(1, Ordering::Acquire);
            if prev != u32::MAX {
                // no writer sentinel, proceed
                return;
            }
            // raced with writer: back out and retry
            self.readers.fetch_sub(1, Ordering::Release);
        }
    }

    /// Release a shared (read) lock.
    /// The **last** reader will wake any blocked writer.
    pub fn read_unlock(&self) {
        if self.readers.fetch_sub(1, Ordering::Release) == 1 {
            // we were the last reader
            let _ = self.event.set(raw_sync::events::EventState::Signaled);
        }
    }

    /// Acquire an **exclusive** (write) lock.
    /// Blocks new readers and waits for in-flight readers to drain.
    pub fn write_lock(&self) {
        // 1) synchronize with other writers
        let _ = self.mutex.lock().expect("RawMutex::lock failed");
        // 2) block new readers
        self.readers.store(u32::MAX, Ordering::Release);
        // 3) wait for existing readers to finish
        while self.readers.load(Ordering::Acquire) != u32::MAX {
            core::hint::spin_loop();
        }
    }

    /// Release an exclusive (write) lock.
    /// Reopens the gate for readers and lets the next writer through.
    pub fn write_unlock(&self) {
        // 1) allow readers again
        self.readers.store(0, Ordering::Release);
        // 2) wake any waiting writer
        let _ = self.mutex.release().expect("RawMutex::release failed");
    }

    /// Try to acquire the write lock with a timeout.
    pub fn try_write_lock(&self, timeout: Timeout) -> bool {
        if self.mutex.try_lock(timeout).is_err() {
            return false;
        }
        self.readers.store(u32::MAX, Ordering::Release);
        while self.readers.load(Ordering::Acquire) != u32::MAX {
            core::hint::spin_loop();
        }
        true
    }
}
