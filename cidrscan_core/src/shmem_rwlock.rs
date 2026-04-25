//! Cross-process read–write lock that fits in shared memory and
//! works on Linux, macOS and Windows.
//! Implements writer preference to avoid starvation.
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use raw_sync::events::{Event as RawEvent, EventImpl, EventInit};
use raw_sync::locks::{LockImpl, LockInit, Mutex as RawMutex};
use raw_sync::Timeout;
use std::{mem::MaybeUninit, sync::Arc};
#[cfg(target_os = "linux")]
use libc::pthread_mutex_consistent;
#[cfg(unix)]
use libc::pthread_mutex_t;

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
}

unsafe impl Send for RawRwLock {}
unsafe impl Sync for RawRwLock {}

pub struct LockHandles {
    pub mutex: Box<dyn LockImpl>,
    pub event: Box<dyn EventImpl>,
}

// SAFETY: raw_sync lock/event handles are process-local wrappers around
// OS synchronization primitives backed by stable shared-memory bytes.
unsafe impl Send for LockHandles {}
unsafe impl Sync for LockHandles {}

const WRITER_BIT: u32 = 0x8000_0000;
const READER_MASK: u32 = WRITER_BIT - 1;

impl RawRwLock {
    /// Safe, cross-platform constructor.
    /// Allocates the backing buffers and initializes the OS handles.
    pub fn new() -> Result<(Box<Self>, LockHandles), crate::errors::Error> {
        let mut lock = Box::new(Self {
            mutex_buf: [0u8; 128],
            event_buf: [0u8; 128],
            readers: AtomicU32::new(0),
        });
        unsafe {
            Self::new_in_place(lock.as_mut() as *mut RawRwLock)?;
            let handles = LockHandles::from_existing(lock.as_ref())?;
            Ok((lock, handles))
        }
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

        // Initialize shared mutex bytes.
        #[cfg(unix)]
        let _ = robust_mutex(this.mutex_buf.as_mut_ptr())
            .map_err(|e| crate::errors::Error::from(format!("robust_mutex init failed: {e}")))?
            .0;
        #[cfg(not(unix))]
        let _ = {
            let (m_raw, _) = RawMutex::new(this.mutex_buf.as_mut_ptr(), ptr::null_mut())
                .map_err(|e: Box<dyn std::error::Error>| crate::errors::Error::Other(format!("mutex init failed: {e}")))?;
            m_raw
        };
        // Initialize shared event bytes.
        let _ = RawEvent::new(this.event_buf.as_mut_ptr(), true)
            .map_err(|e: Box<dyn std::error::Error>| crate::errors::Error::Other(format!("event init failed: {e}")))?;

        Ok(())
    }

    /// Safe, cross-platform constructor that returns an `Arc<Self>`.
    /// Allocates and initializes the lock in-place within the Arc, so internal pointers never move.
    pub fn new_arc() -> Result<(Arc<Self>, LockHandles), crate::errors::Error> {
        // 1. Allocate uninitialized Arc<MaybeUninit<Self>>
        let arc_uninit: Arc<MaybeUninit<Self>> = Arc::new_uninit();
        // 2. Get raw pointer to the inner Self for stable placement
        let ptr = Arc::as_ptr(&arc_uninit) as *mut Self;
        unsafe {
            Self::new_in_place(ptr)?;
        }
        // 5. Convert uninitialized Arc into initialized Arc<Self>
        let arc_self: Arc<Self> = unsafe { <Arc<MaybeUninit<Self>>>::assume_init(arc_uninit) };
        let handles = unsafe { LockHandles::from_existing(arc_self.as_ref())? };
        Ok((arc_self, handles))
    }

    /// Acquire a **shared** (read) lock.
    /// Spins only if a writer holds the lock or is waiting.
    /// Returns a guard that releases the lock when dropped.
    pub fn read_lock<'a>(&'a self, handles: &'a LockHandles) -> ReadGuard<'a> {
        loop {
            let current_readers = self.readers.load(Ordering::Acquire);
            if current_readers & WRITER_BIT != 0 {
                // Wait for writer to release lock
                let _ = handles.event.as_ref().wait(Timeout::Infinite);
                continue;
            }
            match self.readers.compare_exchange_weak(
                current_readers,
                current_readers.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            ) {
                Ok(_) => return ReadGuard { lock: self, handles },
                Err(_) => continue,
            }
        }
    }

    /// Release a shared (read) lock.
    /// Called automatically when ReadGuard is dropped.
    #[inline(never)]
    fn read_unlock(&self, handles: &LockHandles) {
        let prev = self.readers.fetch_sub(1, Ordering::Release);
        if prev == (WRITER_BIT | 1) {
            let _ = self
                .event(handles)
                .set(raw_sync::events::EventState::Signaled);
        }
    }

    /// Acquire an **exclusive** (write) lock.
    /// Blocks new readers and waits for in-flight readers to drain.
    /// Returns a guard that releases the lock when dropped.
    pub fn write_lock<'a>(&'a self, handles: &'a LockHandles) -> Result<WriteGuard<'a>, crate::errors::Error> {
        #[cfg(unix)]
        {
            let result = self.mutex(handles).lock();
            let (guard, recovered_owner_dead) = match result {
                Ok(g) => (Some(g), false),
                Err(e) => {
                    let msg = format!("{}", e);
                    if msg.contains("EOWNERDEAD") {
                        let mtx_ptr = self.mutex_buf.as_ptr() as *mut pthread_mutex_t;
                        #[cfg(target_os = "linux")] {
                            let rc = unsafe { pthread_mutex_consistent(mtx_ptr) };
                            if rc != 0 {
                                return Err(crate::errors::Error::from(format!("pthread_mutex_consistent failed: {rc}")));
                            }
                        }
                        #[cfg(not(target_os = "linux"))] {
                            // no robust support; skip mutex consistency
                        }
                        (None, true)
                    } else {
                        return Err(crate::errors::Error::from(format!("mutex lock failed: {e}")));
                    }
                }
            };
            let evt = self.event(handles);
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
                handles,
                guard,
                recovered_owner_dead,
            })
        }
        #[cfg(not(unix))]
        {
            let guard = self.mutex(handles).lock().map_err(|e| crate::errors::Error::from(format!("mutex lock failed: {e}")))?;
            let evt = self.event(handles);
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
                handles,
                guard: Some(guard),
                recovered_owner_dead: false,
            })
        }
    }

    /// Try to acquire an **exclusive** (write) lock without blocking indefinitely.
    /// Returns Some(WriteGuard) if the lock was acquired, None otherwise.
    pub fn try_write_lock<'a>(&'a self, handles: &'a LockHandles, timeout: Timeout) -> Option<WriteGuard<'a>> {
        let guard = self.mutex(handles).try_lock(timeout).ok()?;
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
            handles,
            guard: Some(guard),
            recovered_owner_dead: false,
        })
    }

    #[inline(always)]
    fn mutex<'a>(&self, handles: &'a LockHandles) -> &'a dyn LockImpl {
        handles.mutex.as_ref()
    }

    #[inline(always)]
    fn event<'a>(&self, handles: &'a LockHandles) -> &'a dyn EventImpl {
        handles.event.as_ref()
    }
}

impl LockHandles {
    /// Open process-local lock/event handles for an existing shared-memory lock.
    ///
    /// Safety: `lock` must point to a fully initialized `RawRwLock` whose
    /// shared byte buffers contain a valid mutex and event.
    pub unsafe fn from_existing(lock: &RawRwLock) -> Result<Self, crate::errors::Error> {
        let mptr = lock.mutex_buf.as_ptr() as *mut u8;
        let eptr = lock.event_buf.as_ptr() as *mut u8;
        let (mutex, _) = RawMutex::from_existing(mptr, ptr::null_mut())
            .map_err(|e| crate::errors::Error::from(format!("re-open mutex failed: {e}")))?;
        let (event, _) = RawEvent::from_existing(eptr)
            .map_err(|e| crate::errors::Error::from(format!("re-open event failed: {e}")))?;
        Ok(Self { mutex, event })
    }
}

/// Represents an acquired exclusive (write) lock.
/// The lock is released when this guard is dropped.
#[must_use = "if unused the lock will immediately unlock"]
pub struct WriteGuard<'a> {
    lock: &'a RawRwLock,
    handles: &'a LockHandles,
    guard: Option<raw_sync::locks::LockGuard<'a>>,
    recovered_owner_dead: bool,
}

impl<'a> Drop for WriteGuard<'a> {
    fn drop(&mut self) {
        self.lock.readers.store(0, Ordering::Release);
        let _ = self
            .lock
            .event(self.handles)
            .set(raw_sync::events::EventState::Signaled);
        if self.recovered_owner_dead {
            let _ = self.handles.mutex.release();
        } else {
            let _ = self.guard.take();
        }
    }
}

/// Represents an acquired shared (read) lock.
/// The lock is released when this guard is dropped.
#[must_use = "if unused the lock will immediately unlock"]
pub struct ReadGuard<'a> {
    lock: &'a RawRwLock,
    handles: &'a LockHandles,
}

impl<'a> Drop for ReadGuard<'a> {
    fn drop(&mut self) {
        self.lock.read_unlock(self.handles);
    }
}
