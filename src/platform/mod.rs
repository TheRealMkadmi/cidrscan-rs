//! Platform-specific module for cidrscan

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(unix)]
pub mod unix;