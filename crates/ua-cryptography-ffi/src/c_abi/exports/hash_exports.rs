//! GOST 34.311-95 and DSTU 7564, one-shot and fed in parts.

use crate::c_abi::call_guard::run_call;
use crate::c_abi::marshalling::{read_bytes, read_optional_bytes, write_buffer};
use crate::c_abi::types::{UaBuffer, UaBytes, UaHashState, UaStatus};
use crate::errors::OperationFailure;
use crate::operations::{StreamingHash, dstu7564, gost34311};

/// GOST 34.311-95 of `data`: 32 bytes, least significant first, as GOST defines H.
///
/// * `dke` — the 64-byte S-box table; NULL `data`: DKE No. 1
/// * `initial_value` — 32 bytes; NULL `data`: zero
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_gost34311_calculate_hash(
    data: UaBytes,
    dke: UaBytes,
    initial_value: UaBytes,
    hash: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let result = gost34311::calculate_hash(
                read_bytes(data, "The data")?,
                read_optional_bytes(dke),
                read_optional_bytes(initial_value),
            )?;
            write_buffer(hash, result)
        })
    }
}

/// DSTU 7564 "Kupyna" of `data`; `hash_bits` is 256, 384 or 512.
///
/// # Safety
/// As `ua_gost34311_calculate_hash`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7564_calculate_hash(
    data: UaBytes,
    hash_bits: u32,
    hash: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let result = dstu7564::calculate_hash(read_bytes(data, "The data")?, hash_bits)?;
            write_buffer(hash, result)
        })
    }
}

/// Begins GOST 34.311-95 of a message fed in parts; `dke` and `initial_value` as in `ua_gost34311_calculate_hash`.
///
/// # Safety
/// As `ua_gost34311_calculate_hash`; `state` points to a writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_gost34311_begin_hash(
    dke: UaBytes,
    initial_value: UaBytes,
    state: *mut *mut UaHashState,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let hash = gost34311::create_hash(read_optional_bytes(dke), read_optional_bytes(initial_value))?;
            write_state(state, StreamingHash::Gost34311(hash))
        })
    }
}

/// Begins DSTU 7564 of `hash_bits` (256, 384, 512) of a message fed in parts.
///
/// # Safety
/// `state` points to a writable pointer; `message` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7564_begin_hash(
    hash_bits: u32,
    state: *mut *mut UaHashState,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let hash = dstu7564::create_hash(hash_bits)?;
            write_state(state, StreamingHash::Dstu7564(hash))
        })
    }
}

/// Absorbs the next part of the message.
///
/// # Safety
/// `state` came from a `…_begin_hash` and is not released; `data` is valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_update_hash(
    state: *mut UaHashState,
    data: UaBytes,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let state = read_state(state)?;
            state.hash.update(read_bytes(data, "The data")?);
            Ok(())
        })
    }
}

/// Ends the hash: writes the hash of everything absorbed and releases `state`, whatever the status.
///
/// # Safety
/// `state` came from a `…_begin_hash` and is not released; it must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_end_hash(
    state: *mut UaHashState,
    hash: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            if state.is_null() {
                return Err(OperationFailure::invalid_argument("The hash state is NULL."));
            }
            let mut state = Box::from_raw(state);
            write_buffer(hash, state.hash.finalize())
        })
    }
}

/// Releases a hash state without ending it; NULL is ignored.
///
/// # Safety
/// `state` came from a `…_begin_hash` and is not released.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_free_hash_state(state: *mut UaHashState) {
    if !state.is_null() {
        // SAFETY: a state boxed by write_state, released once.
        drop(unsafe { Box::from_raw(state) });
    }
}

unsafe fn write_state(target: *mut *mut UaHashState, hash: StreamingHash) -> Result<(), OperationFailure> {
    if target.is_null() {
        return Err(OperationFailure::invalid_argument("The hash state output is NULL."));
    }
    // SAFETY: a non-NULL pointer to a writable pointer.
    unsafe { target.write(Box::into_raw(Box::new(UaHashState { hash }))) };
    Ok(())
}

unsafe fn read_state<'a>(state: *mut UaHashState) -> Result<&'a mut UaHashState, OperationFailure> {
    if state.is_null() {
        return Err(OperationFailure::invalid_argument("The hash state is NULL."));
    }
    // SAFETY: a live state from write_state.
    Ok(unsafe { &mut *state })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c_abi::marshalling::release_buffer;
    use std::ptr;

    fn empty_buffer() -> UaBuffer {
        UaBuffer {
            data: ptr::null_mut(),
            len: 0,
        }
    }

    fn lend(bytes: &[u8]) -> UaBytes {
        UaBytes {
            data: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    fn take(buffer: UaBuffer) -> Vec<u8> {
        let bytes = unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) }.to_vec();
        unsafe { release_buffer(buffer) };
        bytes
    }

    #[test]
    fn a_hash_fed_in_parts_equals_the_one_shot_hash() {
        let mut state: *mut UaHashState = ptr::null_mut();
        let mut whole = empty_buffer();
        let mut parts = empty_buffer();
        unsafe {
            assert_eq!(
                ua_dstu7564_calculate_hash(lend(b"message"), 512, &mut whole, ptr::null_mut()),
                UaStatus::Ok
            );
            assert_eq!(ua_dstu7564_begin_hash(512, &mut state, ptr::null_mut()), UaStatus::Ok);
            assert_eq!(ua_update_hash(state, lend(b"mess"), ptr::null_mut()), UaStatus::Ok);
            assert_eq!(ua_update_hash(state, lend(b"age"), ptr::null_mut()), UaStatus::Ok);
            assert_eq!(ua_end_hash(state, &mut parts, ptr::null_mut()), UaStatus::Ok);
        }
        let whole = take(whole);
        assert_eq!(whole.len(), 64);
        assert_eq!(take(parts), whole);
    }

    #[test]
    fn an_absent_dke_is_dke_no_1() {
        let absent = UaBytes {
            data: ptr::null(),
            len: 0,
        };
        let mut hash = empty_buffer();
        let status =
            unsafe { ua_gost34311_calculate_hash(lend(b"message"), absent, absent, &mut hash, ptr::null_mut()) };
        assert_eq!(status, UaStatus::Ok);
        assert_eq!(take(hash), ua_cryptography_gost::Gost34311::calculate_hash(b"message"));
    }
}
