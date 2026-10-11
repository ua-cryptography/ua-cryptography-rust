//! The library itself: its version and the release of what it hands out.

use std::ffi::{CStr, c_char};

use crate::c_abi::marshalling::release_buffer;
use crate::c_abi::types::UaBuffer;

/// The version of the package, NUL-terminated.
const VERSION: &CStr = match CStr::from_bytes_with_nul(concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes()) {
    Ok(version) => version,
    Err(_) => panic!("the package version has no NUL inside"),
};

/// The library version, e.g. "0.1.0": a static string the caller does not release.
#[unsafe(no_mangle)]
pub extern "C" fn ua_get_version() -> *const c_char {
    VERSION.as_ptr()
}

/// Releases a buffer the library handed out; an empty buffer is ignored. Release each buffer once.
///
/// # Safety
/// `buffer` was written by this library and is not released yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_free_buffer(buffer: UaBuffer) {
    // SAFETY: as the caller promises.
    unsafe { release_buffer(buffer) }
}
