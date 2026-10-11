//! GOST 28147-89 in simple substitution mode over whole 64-bit blocks.

use crate::c_abi::call_guard::run_call;
use crate::c_abi::marshalling::{read_bytes, read_optional_bytes, write_buffer};
use crate::c_abi::types::{UaBuffer, UaBytes, UaStatus};
use crate::operations::gost28147;

/// Encrypts whole 8-byte blocks under the 32-byte `key`; `dke` is the 64-byte table, DKE No. 1 when NULL.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_gost28147_encrypt(
    key: UaBytes,
    dke: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = gost28147::encrypt(
                read_bytes(key, "The key")?,
                read_optional_bytes(dke),
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// Decrypts whole 8-byte blocks under the 32-byte `key`; `dke` is the 64-byte table, DKE No. 1 when NULL.
///
/// # Safety
/// As `ua_gost28147_encrypt`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_gost28147_decrypt(
    key: UaBytes,
    dke: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = gost28147::decrypt(
                read_bytes(key, "The key")?,
                read_optional_bytes(dke),
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}
