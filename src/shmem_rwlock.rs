//! Cross-process read–write lock that fits in shared memory and
//! works on Linux, macOS and Windows.
//! Implements writer preference to avoid starvation.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use raw_sync::events::{EventImpl, EventInit, Event as RawEvent};
use raw_sync::locks::{LockImpl, LockInit, Mutex as RawMutex};
use raw_sync::Timeout;

// Define size constants needed for offset calculations
const MUTEX_SIZE: usize = core::mem::size_of::<RawMutex>();
// const EVENT_SIZE: usize = core::mem::size_of::<RawEvent>(); // Not strictly needed for offsets if event is second

/// Our shared-memory lock layout: [mutex][event][reader_count]
#[repr(C, align(8))]
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
    /// Initialize the lock structure in-place using field addresses.
    /// Returns Ok(()) on success, or an Error if initialization fails.
    ///
    /// Safety: `ptr` must be valid for writes, properly aligned (align(8)),
    /// and point to zeroed memory.
    pub unsafe fn new_in_place(ptr: *mut RawRwLock) -> Result<(), Box<dyn std::error::Error>> {
        // Initialize mutex field directly using its address
        let mutex_ptr = ptr::addr_of_mut!((*ptr).mutex);
        RawMutex::new(mutex_ptr as *mut u8, ptr::null_mut())?;
        // Removed explicit panic, using ? operator

        // Initialize event field directly using its address
        let event_ptr = ptr::addr_of_mut!((*ptr).event);
        RawEvent::new(event_ptr as *mut u8, true)?;
        // Removed expect, using ? operator

        // Initialize readers field directly using its address
        let readers_ptr = ptr::addr_of_mut!((*ptr).readers);
        // ptr::write doesn't return a Result, so no change needed here.
        readers_ptr.write(AtomicU32::new(0));

        Ok(()) // Indicate success
    }

    /// Initialize the lock structure from a raw byte pointer.
    /// This is intended for initialization within a larger struct like Header.
    ///
    /// Safety: `ptr` must point to the beginning of a memory region
    /// suitable for a `RawRwLock`, be valid for writes, properly aligned (align(8)),
    /// and point to zeroed memory. The `timeout` parameter is currently ignored
    /// but kept for potential future compatibility or API consistency.
    pub unsafe fn init(ptr: *mut u8, _timeout: Timeout) -> Result<(), Box<dyn std::error::Error>> {
        // Cast the byte pointer to the specific lock type pointer.
        // This assumes the caller provides the correct starting address.
        let lock_ptr = ptr as *mut RawRwLock;
        // Call the in-place initializer.
        Self::new_in_place(lock_ptr)
    }

    /// Re-open an existing lock in shared memory using field addresses.
    /// Returns Ok(()) on success, or an Error if reopening fails.
    ///
    /// Safety: `ptr` must point at a properly initialized RawRwLock.
    pub unsafe fn reopen_in_place(ptr: *mut RawRwLock) -> Result<(), Box<dyn std::error::Error>> {
        // Reopen mutex field directly using its address
        let mutex_ptr = ptr::addr_of_mut!((*ptr).mutex);
        RawMutex::from_existing(mutex_ptr as *mut u8, ptr::null_mut())?;
        // Removed expect, using ? operator

        // Reopen event field directly using its address
        let event_ptr = ptr::addr_of_mut!((*ptr).event);
        RawEvent::from_existing(event_ptr as *mut u8)?;
        // Removed expect, using ? operator

        // Readers field state is preserved.
        Ok(()) // Indicate success
    }

    /// Represents an acquired exclusive (write) lock.
    /// The lock is released when this guard is dropped.
    #[must_use = "if unused the lock will immediately unlock"]
    pub struct WriteGuard<'a> {
        lock: &'a RawRwLock,
    }

    impl<'a> Drop for WriteGuard<'a> {
        fn drop(&mut self) {
            self.lock.write_unlock();
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
}

impl RawRwLock {
    /// Acquire a **shared** (read) lock.
    /// Spins only if a writer holds the lock or is waiting.
    /// Returns a guard that releases the lock when dropped.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        loop {
            let current_readers = self.readers.load(Ordering::Relaxed);
            if current_readers == u32::MAX {
                core::hint::spin_loop();
                continue;
            }
            match self.readers.compare_exchange_weak(
                current_readers,
                current_readers.wrapping_add(1), // Use wrapping_add for safety
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return ReadGuard { lock: self }, // Return the guard on success
                Err(_) => continue,
            }
        }
    }

    /// Release a shared (read) lock.
    /// Called automatically when `ReadGuard` is dropped.
    fn read_unlock(&self) { // Changed to private, called by ReadGuard::drop
        if self.readers.fetch_sub(1, Ordering::Release) == 1 {
             // We were the last reader *and* no writer had set the MAX sentinel yet.
             // No need to signal here.
        } else {
            // Check if the count *is now* MAX, meaning we were the last reader
            // while a writer was waiting.
            if self.readers.load(Ordering::Acquire) == u32::MAX {
                 // Signal the waiting writer.
                 let _ = self.event.set(raw_sync::events::EventState::Signaled);
            }
        }
    }

    /// Acquire an **exclusive** (write) lock.
    /// Blocks new readers and waits for in-flight readers to drain.
    /// Returns a guard that releases the lock when dropped.
    pub fn write_lock(&self) -> WriteGuard<'_> {
        // 1) Synchronize with other writers
        match self.mutex.lock() {
            Ok(_) => { /* Lock acquired successfully */ }
            Err(e) => {
                // Panic with the specific error from lock()
                panic!("RawMutex::lock failed in write_lock: {:?}", e);
            }
        }
        // 2) Set sentinel to block new readers and get previous count
        let previous_readers = self.readers.swap(u32::MAX, Ordering::Acquire);

        // 3) Wait for existing readers to finish
        if previous_readers > 0 {
            let _ = self.event.set(raw_sync::events::EventState::Clear); // Clear before waiting
            while self.readers.load(Ordering::Acquire) != u32::MAX {
                // Wait for the last reader to signal.
                let _ = self.event.wait(Timeout::Infinite);
            }
        }
        // Mutex acquired, sentinel set, readers drained.
        WriteGuard { lock: self } // Return the guard
    }

    /// Release an exclusive (write) lock.
    /// Called automatically when `WriteGuard` is dropped.
    fn write_unlock(&self) { // Changed to private, called by WriteGuard::drop
        // 1) Allow readers again (remove sentinel)
        self.readers.store(0, Ordering::Release);
        // 2) Release the mutex for other writers
        match self.mutex.release() {
            Ok(_) => { /* Lock released successfully */ }
            Err(e) => {
                // Panic on release failure for clearer debugging during tests
                // Consider logging instead of panicking in production
                panic!("RawMutex::release failed in write_unlock: {:?}", e);
            }
        }
    }

    /// Try to acquire an **exclusive** (write) lock without blocking indefinitely.
    /// Returns `Some(WriteGuard)` if the lock was acquired, `None` otherwise.
    pub fn try_write_lock(&self, timeout: Timeout) -> Option<WriteGuard<'_>> {
        // 1) Try to synchronize with other writers
        let guard = match self.mutex.try_lock(timeout) {
            Ok(guard) => guard, // Successfully acquired the writer mutex guard
            Err(_e) => {
                // Lock not acquired (timeout or other error)
                return None; // Indicate failure
            }
        };

        // We have the mutex guard from raw_sync, now manage readers
        // 2) block new readers by setting sentinel
        let previous_readers = self.readers.swap(u32::MAX, Ordering::Acquire);

        // 3) check if we need to wait for existing readers
        if previous_readers > 0 {
            // Readers were present. Since this is try_lock, we fail immediately.
            // Release the mutex we just acquired by dropping the raw_sync guard.
            // Restore the reader count (best effort, might race).
            self.readers.store(previous_readers, Ordering::Relaxed);
            // Drop the raw_sync guard explicitly to release the mutex *before* returning None
            drop(guard);
            return None; // Indicate failure because readers were present
        }

        // Mutex acquired, sentinel set, no readers were present.
        // Forget the raw_sync guard (so it doesn't release the mutex)
        // and return our own WriteGuard.
        core::mem::forget(guard);
        Some(WriteGuard { lock: self })
    }
}
