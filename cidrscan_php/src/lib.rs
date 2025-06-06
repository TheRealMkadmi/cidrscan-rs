#![cfg_attr(windows, feature(abi_vectorcall))]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use ext_php_rs::exception::PhpException;
use ext_php_rs::prelude::*;

use cidrscan_core as core;
use core::constants::TAG_MAX_LEN;
use core::{
    cidr_available_capacity, cidr_clear as core_cidr_clear, cidr_close as core_cidr_close, cidr_delete as core_cidr_delete, cidr_flush as core_cidr_flush, 
    cidr_force_destroy, cidr_insert as core_cidr_insert, cidr_lookup as core_cidr_lookup, 
    cidr_lookup_full as core_cidr_lookup_full, cidr_open as core_cidr_open, cidr_resize as core_cidr_resize, cidr_strerror,
    PatriciaHandle, PatriciaMatchT,
};
use cidrscan_core::errors::ErrorCode;

/// Handle type for CIDR scanner instances - now using safe handle IDs
pub type CidrHandle = u64;

/// Match information returned by cidrscan_match function
#[derive(Debug, Clone)]
#[php_class]
pub struct CidrMatch {
    /// High part of the network key
    pub key_high: i64,
    
    /// Low part of the network key  
    pub key_low: i64,
    
    /// Prefix length (e.g., 24 for /24)
    pub prefix_length: i64,
    
    /// Associated tag string
    pub tag: String,
}

#[php_impl]
impl CidrMatch {
    /// Create a new CidrMatch instance
    pub fn __construct(key_high: i64, key_low: i64, prefix_length: i64, tag: String) -> Self {
        Self {
            key_high,
            key_low,
            prefix_length,
            tag,
        }
    }
    
    /// Get the CIDR notation string representation
    pub fn get_cidr_string(&self) -> String {
        // This would need to be implemented based on the key format
        format!("key_high:{}, key_low:{}, /{}", self.key_high, self.key_low, self.prefix_length)
    }
}

// ───────────────────────── helpers ──────────────────────────────────── //

/// Convert an `ErrorCode` into a `PhpException` using `cidr_strerror`.
fn map_error_to_exception(code: ErrorCode) -> PhpException {
    let msg = unsafe { CStr::from_ptr(cidr_strerror(code)) }
        .to_string_lossy()
        .into_owned();
    PhpException::default(msg)
}

/// Convert a Rust `&str` to a nul-terminated `CString`.
#[inline]
fn str_to_cstring(s: &str) -> Result<CString, PhpException> {
    CString::new(s).map_err(|_| PhpException::default("String contains NUL byte".into()))
}

/// Validate handle ID
#[inline]
fn validate_handle(handle: CidrHandle) -> Result<PatriciaHandle, PhpException> {
    if handle == 0 {
        return Err(PhpException::default("Invalid handle: cannot be zero".into()));
    }
    Ok(handle)
}

// ───────────────────────── lifetime ──────────────────────────────────── //

/// Open or create a shared-memory CIDR scanner arena.
/// 
/// # Parameters
/// * `name` - Name of the shared memory segment
/// * `capacity` - Maximum number of entries the arena can hold
/// 
/// # Returns
/// Handle to the CIDR scanner instance on success
#[php_function]
pub fn cidr_open(name: String, capacity: u64) -> PhpResult<CidrHandle> {
    let name_cstr = str_to_cstring(&name)?;
    let mut handle: PatriciaHandle = 0;
    
    let result = core_cidr_open(name_cstr.as_ptr(), capacity.try_into().unwrap(), &mut handle);
    match result {
        ErrorCode::Success => Ok(handle),
        error_code => Err(map_error_to_exception(error_code))
    }
}

/// Close a CIDR scanner handle and free associated resources.
/// 
/// # Parameters  
/// * `handle` - Handle to the CIDR scanner instance
/// 
/// # Returns
/// True on success
#[php_function]
pub fn cidr_close(handle: CidrHandle) -> PhpResult<bool> {
    let handle_id = validate_handle(handle)?;
    let result = core_cidr_close(handle_id);
    match result {
        ErrorCode::Success => Ok(true),
        error_code => Err(map_error_to_exception(error_code))
    }
}

// ───────────────────────── CRUD operations ──────────────────────────── //

/// Insert a CIDR prefix into the scanner.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance
/// * `cidr` - CIDR notation string (e.g., "192.168.1.0/24")
/// * `ttl` - Time-to-live in seconds (0 for permanent)
/// * `tag` - Optional tag string to associate with this prefix
/// 
/// # Returns
/// True on success
#[php_function]
pub fn cidr_insert(handle: CidrHandle, cidr: String, ttl: u64, tag: Option<String>) -> PhpResult<bool> {
    let handle_id = validate_handle(handle)?;
    let cidr_cstr = str_to_cstring(&cidr)?;
    
    let (_tag_cstr, tag_ptr): (Option<CString>, *const c_char) = match tag {
        Some(t) => {
            let tag_cstring = str_to_cstring(&t)?;
            let ptr = tag_cstring.as_ptr();
            (Some(tag_cstring), ptr)
        },
        None => (None, ptr::null()),
    };
    
    let result = core_cidr_insert(handle_id, cidr_cstr.as_ptr(), ttl, tag_ptr);
    match result {
        ErrorCode::Success => Ok(true),
        error_code => Err(map_error_to_exception(error_code))
    }
}

/// Remove a CIDR prefix from the scanner.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance  
/// * `cidr` - CIDR notation string to remove
/// 
/// # Returns
/// True on success
#[php_function]
pub fn cidr_delete(handle: CidrHandle, cidr: String) -> PhpResult<bool> {
    let handle_id = validate_handle(handle)?;
    let cidr_cstr = str_to_cstring(&cidr)?;
    
    let result = core_cidr_delete(handle_id, cidr_cstr.as_ptr());
    match result {
        ErrorCode::Success => Ok(true),
        error_code => Err(map_error_to_exception(error_code))
    }
}

/// Check if an IP address matches any stored CIDR prefix.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance
/// * `addr` - IP address string to check
/// 
/// # Returns
/// `true` if the address matches a stored prefix, `false` otherwise
#[php_function]
pub fn cidr_lookup(handle: CidrHandle, addr: String) -> PhpResult<bool> {
    let handle_id = validate_handle(handle)?;
    let addr_cstr = str_to_cstring(&addr)?;
    let mut found: bool = false;
    
    let result = core_cidr_lookup(handle_id, addr_cstr.as_ptr(), &mut found);
    match result {
        ErrorCode::Success => Ok(found),
        error_code => Err(map_error_to_exception(error_code))
    }
}

/// Get detailed information about a matching CIDR prefix.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance
/// * `addr` - IP address string to check
/// 
/// # Returns
/// CidrMatch object with match details, or null if no match found
#[php_function]
pub fn cidrscan_match(handle: CidrHandle, addr: String) -> PhpResult<Option<CidrMatch>> {
    let handle_id = validate_handle(handle)?;
    let addr_cstr = str_to_cstring(&addr)?;
    let mut match_info = PatriciaMatchT {
        key_high: 0,
        key_low: 0,
        plen: 0,
        tag: [0; TAG_MAX_LEN],
    };
      let result = core_cidr_lookup_full(handle_id, addr_cstr.as_ptr(), &mut match_info);
    match result {
        ErrorCode::Success => {
            // Convert the tag from C string
            let tag_cstr = unsafe { CStr::from_ptr(match_info.tag.as_ptr()) };
            let tag_string = tag_cstr.to_string_lossy().into_owned();
            
            Ok(Some(CidrMatch {
                key_high: match_info.key_high as i64,
                key_low: match_info.key_low as i64,
                prefix_length: match_info.plen as i64,
                tag: tag_string,
            }))
        },
        ErrorCode::NotFound => Ok(None),
        error_code => Err(map_error_to_exception(error_code))
    }
}

// ───────────────────── capacity & maintenance ───────────────────────── //

/// Get the number of available slots in the scanner.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance
/// 
/// # Returns
/// Number of available capacity slots
#[php_function]
pub fn cidr_get_capacity(handle: CidrHandle) -> PhpResult<u64> {
    let handle_id = validate_handle(handle)?;
    let mut capacity: u64 = 0;
    
    let result = cidr_available_capacity(handle_id, &mut capacity);
    match result {
        ErrorCode::Success => Ok(capacity),
        error_code => Err(map_error_to_exception(error_code))
    }
}

/// Flush expired entries and perform maintenance on the scanner.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance
/// 
/// # Returns
/// True on success
#[php_function]
pub fn cidr_flush(handle: CidrHandle) -> PhpResult<bool> {
    let handle_id = validate_handle(handle)?;
    
    let result = core_cidr_flush(handle_id);
    match result {
        ErrorCode::Success => Ok(true),
        error_code => Err(map_error_to_exception(error_code))
    }
}

/// Clear all entries from the scanner.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance
/// 
/// # Returns
/// True on success
#[php_function]
pub fn cidr_clear(handle: CidrHandle) -> PhpResult<bool> {
    let handle_id = validate_handle(handle)?;
    
    let result = core_cidr_clear(handle_id);
    match result {
        ErrorCode::Success => Ok(true),
        error_code => Err(map_error_to_exception(error_code))
    }
}

/// Resize the scanner's capacity.
/// 
/// # Parameters
/// * `handle` - Handle to the CIDR scanner instance
/// * `new_capacity` - New maximum number of entries
/// 
/// # Returns
/// True on success
#[php_function]
pub fn cidr_resize(handle: CidrHandle, new_capacity: u64) -> PhpResult<bool> {
    let handle_id = validate_handle(handle)?;
    
    let result = core_cidr_resize(handle_id, new_capacity.try_into().unwrap());
    match result {
        ErrorCode::Success => Ok(true),
        error_code => Err(map_error_to_exception(error_code))
    }
}

// ───────────────────── utility functions ─────────────────────────────── //

/// Get a human-readable error message for an error code.
/// 
/// # Parameters
/// * `error_code` - Error code value
/// 
/// # Returns
/// Human-readable error message
#[php_function]
pub fn cidr_error_message(error_code: i64) -> PhpResult<String> {
    let code_enum = match error_code {
        0 => ErrorCode::Success,
        1 => ErrorCode::CapacityExceeded,
        2 => ErrorCode::ZeroCapacity,
        3 => ErrorCode::InvalidPrefix,
        4 => ErrorCode::BranchHasChildren,
        5 => ErrorCode::InvalidHandle,
        6 => ErrorCode::Utf8Error,
        7 => ErrorCode::LockInitFailed,
        8 => ErrorCode::ShmemOpenFailed,
        9 => ErrorCode::ResizeFailed,
        10 => ErrorCode::FlushFailed,
        11 => ErrorCode::TagTooLong,
        12 => ErrorCode::NotFound,
        255 => ErrorCode::Unknown,
        _ => return Err(PhpException::default("Invalid error code".into())),
    };
    
    let message = unsafe { 
        CStr::from_ptr(cidr_strerror(code_enum))
            .to_string_lossy()
            .into_owned()
    };
    Ok(message)
}

/// Force destroy a shared memory segment by name.
/// 
/// # Parameters
/// * `name` - Name of the shared memory segment to destroy
/// 
/// # Returns
/// True on success
#[php_function]
pub fn cidr_destroy(name: String) -> PhpResult<bool> {
    let name_cstr = str_to_cstring(&name)?;
    
    let result = cidr_force_destroy(name_cstr.as_ptr());
    match result {
        ErrorCode::Success => Ok(true),
        error_code => Err(map_error_to_exception(error_code))
    }
}

// ───────────────────── module registration ──────────────────────────── //

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
