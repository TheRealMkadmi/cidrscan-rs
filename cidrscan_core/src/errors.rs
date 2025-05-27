//! Error handling and C-ABI error codes for cidrscan

use std::cell::RefCell;
use std::os::raw::c_char;

/// Error type for PatriciaTree operations and C-ABI error codes for cidrscan

use std::fmt;
#[derive(Debug)]
pub enum Error {
    CapacityExceeded,
    ZeroCapacity,
    InvalidPrefix,
    BranchHasChildren,
    LockInitFailed,
    TagTooLong,
    Lock(String),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CapacityExceeded => write!(f, "Capacity exceeded"),
            Error::ZeroCapacity => write!(f, "Zero capacity is not allowed"),
            Error::InvalidPrefix => write!(f, "Invalid prefix"),
            Error::BranchHasChildren => write!(f, "Branch has children"),
            Error::LockInitFailed => write!(f, "Failed to initialize in-place RW-lock"),
            Error::TagTooLong => write!(f, "Tag string exceeds maximum allowed length"),
            Error::Lock(msg) => write!(f, "Lock error: {msg}"),
            Error::Other(msg) => write!(f, "Other error: {msg}"),
        }
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Error::Other(msg)
    }
}

impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        Error::Other(msg.to_string())
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    Success = 0,
    CapacityExceeded = 1,
    ZeroCapacity = 2,
    InvalidPrefix = 3,
    BranchHasChildren = 4,
    InvalidHandle = 5,
    Utf8Error = 6,
    LockInitFailed = 7,
    ShmemOpenFailed = 8,
    ResizeFailed = 9,
    FlushFailed = 10,
    TagTooLong = 11,
    NotFound = 12,
    Unknown = 255,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Success => "Success",
            ErrorCode::CapacityExceeded => "Capacity exceeded",
            ErrorCode::ZeroCapacity => "Zero capacity",
            ErrorCode::InvalidPrefix => "Invalid prefix",
            ErrorCode::BranchHasChildren => "Branch has children",
            ErrorCode::InvalidHandle => "Invalid handle",
            ErrorCode::Utf8Error => "UTF-8 conversion error",
            ErrorCode::LockInitFailed => "Lock initialization failed",
            ErrorCode::ShmemOpenFailed => "Shared memory open failed",
            ErrorCode::ResizeFailed => "Resize operation failed",
            ErrorCode::FlushFailed => "Flush operation failed",
            ErrorCode::TagTooLong => "Tag too long",
            ErrorCode::NotFound => "Not found",
            ErrorCode::Unknown => "Unknown error",
        }
    }
}

// Thread-local last error for C-ABI
thread_local! {
    static LAST_ERROR: RefCell<ErrorCode> = RefCell::new(ErrorCode::Success);
}

pub fn set_last_error(code: ErrorCode) {
    LAST_ERROR.with(|cell| *cell.borrow_mut() = code);
}

pub fn get_last_error() -> ErrorCode {
    LAST_ERROR.with(|cell| *cell.borrow())
}

#[no_mangle]
pub extern "C" fn patricia_last_error() -> ErrorCode {
    get_last_error()
}

#[no_mangle]
pub extern "C" fn patricia_strerror(code: ErrorCode) -> *const c_char {
    match code {
        ErrorCode::Success => b"Success\0".as_ptr() as *const c_char,
        ErrorCode::CapacityExceeded => b"Capacity exceeded\0".as_ptr() as *const c_char,
        ErrorCode::ZeroCapacity => b"Zero capacity\0".as_ptr() as *const c_char,
        ErrorCode::InvalidPrefix => b"Invalid prefix\0".as_ptr() as *const c_char,
        ErrorCode::BranchHasChildren => b"Branch has children\0".as_ptr() as *const c_char,
        ErrorCode::InvalidHandle => b"Invalid handle\0".as_ptr() as *const c_char,
        ErrorCode::Utf8Error => b"UTF-8 conversion error\0".as_ptr() as *const c_char,
        ErrorCode::LockInitFailed => b"Lock initialization failed\0".as_ptr() as *const c_char,
        ErrorCode::ShmemOpenFailed => b"Shared memory open failed\0".as_ptr() as *const c_char,
        ErrorCode::ResizeFailed => b"Resize operation failed\0".as_ptr() as *const c_char,
        ErrorCode::FlushFailed => b"Flush operation failed\0".as_ptr() as *const c_char,
        ErrorCode::TagTooLong => b"Tag too long\0".as_ptr() as *const c_char,
        ErrorCode::NotFound => b"Not found\0".as_ptr() as *const c_char,
        ErrorCode::Unknown => b"Unknown error\0".as_ptr() as *const c_char,
    }
}

// Map internal Error to ErrorCode
pub fn map_error(e: &Error) -> ErrorCode {
    match e {
        Error::CapacityExceeded => ErrorCode::CapacityExceeded,
        Error::ZeroCapacity => ErrorCode::ZeroCapacity,
        Error::InvalidPrefix => ErrorCode::InvalidPrefix,
        Error::BranchHasChildren => ErrorCode::BranchHasChildren,
        Error::LockInitFailed => ErrorCode::LockInitFailed,
        Error::TagTooLong => ErrorCode::TagTooLong,
        Error::Lock(_) => ErrorCode::LockInitFailed, // Map lock errors to LockInitFailed
        Error::Other(_) => ErrorCode::Unknown,
    }
}