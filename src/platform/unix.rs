//! Unix-specific platform code for cidrscan

#[cfg(unix)]
pub fn platform_drop(os_id: &str) {
    use std::ffi::CString;
    unsafe {
        if let Ok(c_name) = CString::new(os_id) {
            let _ = libc::shm_unlink(c_name.as_ptr());
        }
    }
}