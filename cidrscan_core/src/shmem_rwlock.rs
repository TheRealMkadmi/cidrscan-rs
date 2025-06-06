//! Cross-process read–write lock that fits in shared memory and
//! works on Linux, macOS and Windows.
//! Implements writer preference to avoid starvation.
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use raw_sync::events::{Event as RawEvent, EventImpl, EventInit};
use raw_sync::locks::{LockImpl, LockInit, Mutex as RawMutex};
use raw_sync::Timeout;
use core::marker::PhantomData;
use memoffset::offset_of;
use crate::Header;
use std::{mem::MaybeUninit, sync::Arc};
#[cfg(unix)]
use libc::{pthread_mutex_consistent, pthread_mutex_t};

#[cfg(unix)]
use crate::platform::unix::robust_mutex;

const _: () = {
    assert!(core::mem::size_of::<RawRwLock>() % core::mem::align_of::<RawRwLock>() == 0);
};

#[repr(C, align(8))]
pub struct RawRwLock {
    mutex_buf: [u8; 128],
    event_buf: [u8; 128],
    pub readers: AtomicU32,
    mutex_handle: Option<Box<dyn LockImpl>>,
    event_handle: Option<Box<dyn EventImpl>>,
    _marker: PhantomData<()>,
}

unsafe impl Send for RawRwLock {}
unsafe impl Sync for RawRwLock {}

const WRITER_BIT: u32 = 0x8000_0000;
const READER_MASK: u32 = WRITER_BIT - 1;

impl RawRwLock {
    #[inline(always)]
    fn mutex(&self) -> &dyn LockImpl {
        self.mutex_handle
            .as_ref()
            .expect("mutex_handle not initialized (should be initialized in new/new_in_place/reopen_in_place)")
            .as_ref()
    }

    #[inline(always)]
    fn event(&self) -> &dyn EventImpl {
        self.event_handle
            .as_ref()
            .expect("event_handle not initialized (should be initialized in new/new_in_place/reopen_in_place)")
            .as_ref()
    }

    /// Safe, cross-platform constructor.
    /// Allocates the backing buffers and initializes the OS handles.
    pub fn new() -> Result<Box<Self>, crate::errors::Error> {
        let msz = RawMutex::size_of(None);
        let esz = RawEvent::size_of(None);

        debug_assert!(msz <= 128);
        debug_assert!(esz <= 128);

        let mut lock = Box::new(Self {
            mutex_buf: [0u8; 128],
            event_buf: [0u8; 128],
            readers: AtomicU32::new(0),
            mutex_handle: None,
            event_handle: None,
            _marker: PhantomData,
        });

        unsafe {
            let (m_raw, _) = RawMutex::new(lock.mutex_buf.as_mut_ptr(), ptr::null_mut())
                .map_err(|e| crate::errors::Error::from(format!("mutex init failed: {e}")))?;
            let m_box: Box<dyn LockImpl> = m_raw;
            let (e_box, _) = RawEvent::new(lock.event_buf.as_mut_ptr(), true)
                .map_err(|e| crate::errors::Error::from(format!("event init failed: {e}")))?;
            lock.mutex_handle = Some(m_box);
            lock.event_handle = Some(e_box);
        }
        Ok(lock)
    }

    /// In-place initialization for shared memory usage.
    /// # Safety
    /// - `ptr` must be valid and properly aligned.
    pub unsafe fn new_in_place(ptr: *mut RawRwLock) -> Result<(), crate::errors::Error> {
        // Zero entire RawRwLock memory so readers starts at 0 even if caller forgets to supply zeroed memory
        ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<RawRwLock>());
        let this = &mut *ptr;
        let msz = RawMutex::size_of(None);
        let esz = RawEvent::size_of(None);

        debug_assert!(msz <= 128);
        debug_assert!(esz <= 128);

        this.mutex_buf = [0u8; 128];
        this.event_buf = [0u8; 128];
        this.readers = AtomicU32::new(0);
        this.mutex_handle = None;
        this.event_handle = None;

        // Initialize mutex handle as Box<dyn LockImpl>
        #[cfg(unix)]
        let m_box: Box<dyn LockImpl> = robust_mutex(this.mutex_buf.as_mut_ptr())
            .map_err(|e| crate::errors::Error::from(format!("robust_mutex init failed: {e}")))?
            .0;
        #[cfg(not(unix))]
        let m_box: Box<dyn LockImpl> = {
            let (m_raw, _) = RawMutex::new(this.mutex_buf.as_mut_ptr(), ptr::null_mut())
                .map_err(|e: Box<dyn std::error::Error>| crate::errors::Error::Other(format!("mutex init failed: {e}")))?;
            m_raw
        };
        // Initialize event handle
        let (e_box, _) = RawEvent::new(this.event_buf.as_mut_ptr(), true)
            .map_err(|e: Box<dyn std::error::Error>| crate::errors::Error::Other(format!("event init failed: {e}")))?;
        this.mutex_handle = Some(m_box);
        this.event_handle = Some(e_box);

        Ok(())
    }

    /// Re-open an existing lock in shared memory using field addresses.
    /// Returns Ok(()) on success, or an Error if reopening fails.
    ///
    /// Safety: ptr must point at a properly initialized RawRwLock.
    pub unsafe fn reopen_in_place(ptr: *mut RawRwLock) -> Result<(), crate::errors::Error> {
        if ptr.is_null() {
            return Err(crate::errors::Error::from("Null pointer passed to reopen_in_place"));
        }

        let this = &mut *ptr;
        let mptr = this.mutex_buf.as_mut_ptr() as *mut u8;
        let eptr = this.event_buf.as_mut_ptr() as *mut u8;
        let (mutex, _) = RawMutex::from_existing(mptr, ptr::null_mut())
            .map_err(|e| crate::errors::Error::from(format!("re-open mutex failed: {e}")))?;
        let (event, _) =
            RawEvent::from_existing(eptr).map_err(|e| crate::errors::Error::from(format!("re-open event failed: {e}")))?;
        this.mutex_handle = Some(mutex);
        this.event_handle = Some(event);

        Ok(()) // Indicate success
    }
    // Readers field state is preserved.

    /// Safe, cross-platform constructor that returns an `Arc<Self>`.
    /// Allocates and initializes the lock in-place within the Arc, so internal pointers never move.
    pub fn new_arc() -> Result<Arc<Self>, crate::errors::Error> {
        // 1. Allocate uninitialized Arc<MaybeUninit<Self>>
        let arc_uninit: Arc<MaybeUninit<Self>> = Arc::new_uninit();
        // 2. Get raw pointer to the inner Self for stable placement
        let ptr = Arc::as_ptr(&arc_uninit) as *mut Self;
        unsafe {
            // 3. Construct Self in-place
            ptr.write(Self {
                mutex_buf: [0u8; 128],
                event_buf: [0u8; 128],
                readers: AtomicU32::new(0),
                mutex_handle: None,
                event_handle: None,
                _marker: PhantomData,
            });
            // 4. Initialize OS handles in-place
            let (raw_mtx, _) = RawMutex::new((*ptr).mutex_buf.as_mut_ptr(), ptr::null_mut())
                .map_err(|e| crate::errors::Error::from(format!("mutex init failed: {e}")))?;
            let (raw_evt, _) = RawEvent::new((*ptr).event_buf.as_mut_ptr(), true)
                .map_err(|e| crate::errors::Error::from(format!("event init failed: {e}")))?;
            (*ptr).mutex_handle = Some(raw_mtx);
            (*ptr).event_handle = Some(raw_evt);
        }
        // 5. Convert uninitialized Arc into initialized Arc<Self>
        let arc_self: Arc<Self> = unsafe { <Arc<MaybeUninit<Self>>>::assume_init(arc_uninit) };
        Ok(arc_self)
    }

    /// Acquire a **shared** (read) lock.
    /// Spins only if a writer holds the lock or is waiting.
    /// Returns a guard that releases the lock when dropped.
    pub fn read_lock(&self) -> ReadGuard<'_> {
        loop {
            let current_readers = self.readers.load(Ordering::Acquire);
            if current_readers & WRITER_BIT != 0 {
                // Wait for writer to release lock
                let _ = self.event().wait(Timeout::Infinite);
                continue;
            }
            match self.readers.compare_exchange_weak(
                current_readers,
                current_readers.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return ReadGuard { lock: self },
                Err(_) => continue,
            }
        }
    }

    /// Release a shared (read) lock.
    /// Called automatically when ReadGuard is dropped.
    #[inline(never)]
    fn read_unlock(&self) {
        let prev = self.readers.fetch_sub(1, Ordering::Release);
        if prev == (WRITER_BIT | 1) {
            let _ = self
                .event()
                .set(raw_sync::events::EventState::Signaled);
        }
    }

    /// Acquire an **exclusive** (write) lock.
    /// Blocks new readers and waits for in-flight readers to drain.
    /// Returns a guard that releases the lock when dropped.
    pub fn write_lock(&self) -> Result<WriteGuard<'_>, crate::errors::Error> {
        #[cfg(unix)]
        {
            let result = self.mutex().lock();
            let guard = match result {
                Ok(g) => g,
                Err(e) => {
                    let msg = format!("{}", e);
                    if msg.contains("EOWNERDEAD") {
                        unsafe {
                            let hdr_ptr = (self as *const _ as *const u8)
                                .offset(-(offset_of!(Header, lock) as isize))
                                as *const Header;
                            let _ = (*hdr_ptr).ref_count.fetch_update(
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                                |v| if v > 0 { Some(v - 1) } else { None },
                            );
                        }
                        let mtx_ptr = self.mutex_buf.as_ptr() as *mut pthread_mutex_t;
                        let rc = unsafe { pthread_mutex_consistent(mtx_ptr) };
                        if rc != 0 {
                            return Err(crate::errors::Error::from(format!("pthread_mutex_consistent failed: {rc}")));
                        }
                        self.mutex().lock().map_err(|e| crate::errors::Error::from(format!("mutex lock failed after recovery: {e}")))?
                    } else {
                        return Err(crate::errors::Error::from(format!("mutex lock failed: {e}")));
                    }
                }
            };
            let evt = self.event();
            evt.set(raw_sync::events::EventState::Clear)
                .map_err(|e| crate::errors::Error::from(format!("event clear failed: {e}")))?;
            let prev = self.readers.fetch_or(WRITER_BIT, Ordering::AcqRel) & READER_MASK;
            if prev != 0 {
                evt.wait(Timeout::Infinite)
                    .map_err(|e| crate::errors::Error::from(format!("event wait failed: {e}")))?;
                while self.readers.load(Ordering::Acquire) != WRITER_BIT {
                    core::hint::spin_loop();
                }
            }
            Ok(WriteGuard {
                lock: self,
                _guard: guard,
            })
        }
        #[cfg(not(unix))]
        {
            let guard = self.mutex().lock().map_err(|e| crate::errors::Error::from(format!("mutex lock failed: {e}")))?;
            let evt = self.event();
            evt.set(raw_sync::events::EventState::Clear)
                .map_err(|e| crate::errors::Error::from(format!("event clear failed: {e}")))?;
            let prev = self.readers.fetch_or(WRITER_BIT, Ordering::AcqRel) & READER_MASK;
            if prev != 0 {
                evt.wait(Timeout::Infinite)
                    .map_err(|e| crate::errors::Error::from(format!("event wait failed: {e}")))?;
                while self.readers.load(Ordering::Acquire) != WRITER_BIT {
                    core::hint::spin_loop();
                }
            }
            Ok(WriteGuard {
                lock: self,
                _guard: guard,
            })
        }
    }

    /// Try to acquire an **exclusive** (write) lock without blocking indefinitely.
    /// Returns Some(WriteGuard) if the lock was acquired, None otherwise.
    pub fn try_write_lock(&self, timeout: Timeout) -> Option<WriteGuard<'_>> {
        let guard = self.mutex().try_lock(timeout).ok()?;
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
        self.lock.readers.store(0, Ordering::Release);
        let _ = self
            .lock
            .event()
            .set(raw_sync::events::EventState::Signaled);
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
