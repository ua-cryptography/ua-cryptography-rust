use std::ffi::c_char;

use crate::c_abi::types::UaBytes;

/// A file lent for one call: its name (UTF-8, NUL-terminated) and its content.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UaNamedBytes {
    /// The file name, as a XAdES reference or an ASiC entry names it.
    pub name: *const c_char,
    /// The content.
    pub content: UaBytes,
}
