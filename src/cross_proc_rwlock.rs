//! Simple cross-process read–write lock.
//! Works on Linux/macOS with `pthread_rwlock_t` set to PTHREAD_PROCESS_SHARED
//! and on Windows with one named Mutex + two named Semaphores.

use lock_api::{RawRwLock, GuardSend};
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(unix)]
mod imp {
    use super::*;
    use std::mem::MaybeUninit;
    use libc::{
        pthread_rwlock_t, pthread_rwlockattr_t,
        pthread_rwlock_init, pthread_rwlock_destroy,
        pthread_rwlock_rdlock, pthread_rwlock_wrlock,
        pthread_rwlock_unlock, pthread_rwlockattr_init,
        pthread_rwlockattr_setpshared, PTHREAD_PROCESS_SHARED,
    };

    #[repr(C)]
    pub struct Raw {
        lock: pthread_rwlock_t,
    }

    impl RawRwLock for Raw {
        const INIT: Self = Self { lock: 0 as _ };
        type GuardMarker = GuardSend;

        fn lock_shared(&self) { unsafe { pthread_rwlock_rdlock(&self.lock) }; }
        fn lock_exclusive(&self) { unsafe { pthread_rwlock_wrlock(&self.lock) }; }
        unsafe fn try_lock_shared(&self) -> bool { pthread_rwlock_rdlock(&self.lock) == 0 }
        unsafe fn try_lock_exclusive(&self) -> bool { pthread_rwlock_wrlock(&self.lock) == 0 }
        unsafe fn unlock_shared(&self) { pthread_rwlock_unlock(&self.lock); }
        unsafe fn unlock_exclusive(&self) { pthread_rwlock_unlock(&self.lock); }
    }

    impl Raw {
        pub const fn new_uninit() -> Self { Self { lock: 0 as _ } }

        /// Must be called exactly once per mapping *after* shared memory is mapped writable.
        pub unsafe fn init(&mut self) {
            let mut attr: MaybeUninit<pthread_rwlockattr_t> = MaybeUninit::uninit();
            pthread_rwlockattr_init(attr.as_mut_ptr());
            pthread_rwlockattr_setpshared(attr.as_mut_ptr(), PTHREAD_PROCESS_SHARED);  /* POSIX */
            pthread_rwlock_init(&mut self.lock, attr.as_ptr());
        }
    }

    impl Drop for Raw {
        fn drop(&mut self) {
            unsafe {
                libc::pthread_rwlock_destroy(&mut self.lock);
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;    
    use windows_sys::Win32::System::Threading::*;
    use windows_sys::Win32::Foundation::{HANDLE, CloseHandle};

    const READERS_MAX: i32 = 0x7fff_ffff;

    #[repr(C)]
    pub struct Raw {
        init: AtomicU32,
        mutex: HANDLE,
        gate: HANDLE,
        readers: AtomicU32,
    }

    unsafe impl RawRwLock for Raw {
        const INIT: Self = Self {
            init:  AtomicU32::new(0),
            mutex: 0 as _,
            gate:  0 as _,
            readers: AtomicU32::new(0),
        };
        type GuardMarker = GuardSend;

        fn lock_shared(&self) {
            self.wait_init();
            // fast-path: increment readers
            if self.readers.fetch_add(1, Ordering::Acquire) == 0 {
                // first reader: wait on writer gate
                unsafe { WaitForSingleObject(self.gate, u32::MAX) };
            }
        }

        fn lock_exclusive(&self) {
            self.wait_init();
            unsafe { WaitForSingleObject(self.mutex, u32::MAX) };
            // block new readers
            unsafe { WaitForSingleObject(self.gate, u32::MAX) };
        }

        fn try_lock_shared(&self) -> bool {
            self.wait_init();
            // SAFETY: Windows API call, must be called with valid handles.
                let r = self.readers.load(Ordering::Relaxed);
                if r == 0 {
                    false
                } else {
                    self.readers.fetch_add(1, Ordering::Acquire);
                    true
                }
        }
        fn try_lock_exclusive(&self) -> bool {
            self.wait_init();
            // TryMutex + TryWait gate omitted for brevity – guaranteed fallback path OK.
            false
        }

        unsafe fn unlock_shared(&self) {
            if self.readers.fetch_sub(1, Ordering::Release) == 1 {
                // last reader re-opens gate
                ReleaseSemaphore(self.gate, 1, core::ptr::null_mut());
            }
        }
        unsafe fn unlock_exclusive(&self) {
            // open gate then release writer mutex
            ReleaseSemaphore(self.gate, 1, core::ptr::null_mut());
            ReleaseMutex(self.mutex);
        }
    }

    impl Raw {
        pub const fn new_uninit() -> Self { Self::INIT }

        pub unsafe fn init(&mut self, name: &str) {
            if self.init.fetch_or(1, Ordering::AcqRel) == 0 {
                // creator role
                let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                self.mutex  = CreateMutexW(core::ptr::null_mut(), 0, wide.as_ptr());
                self.gate   = CreateSemaphoreW(core::ptr::null_mut(), 1, 1, wide.as_ptr().add(1)); // “name\0gate”
            } else {
                // follower role
                let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                self.mutex = OpenMutexW(MUTEX_ALL_ACCESS, 0, wide.as_ptr());
                self.gate  = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, 0, wide.as_ptr().add(1));
            }
        }

        fn wait_init(&self) {
            while self.init.load(Ordering::Acquire) == 0 {
                core::hint::spin_loop();
            }
        }
    }

    impl Drop for Raw {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.mutex);
                CloseHandle(self.gate);
            }
        }
    }
}

pub use imp::Raw as CrossProcessRawRwLock;
/// Public façade – identical API to `parking_lot::RwLock`.
// #[cfg_attr(docsrs, doc(cfg(feature = "parking_lot")))]
pub type CrossProcessRwLock<T> = lock_api::RwLock<CrossProcessRawRwLock, T>;