//! Reading what the caller lends and writing what the library hands out. Every raw pointer of the C ABI is
//! dereferenced here.

use std::ffi::{CStr, c_char};
use std::{ptr, slice};

use ua_cryptography_pki::{SignatureLevel, SignedFile};

use crate::c_abi::types::{
    UA_CURVE_BASIS_OPTIMAL_NORMAL, UA_CURVE_BASIS_POLYNOMIAL, UA_SIGNATURE_FORMAT_ASIC_E, UA_SIGNATURE_FORMAT_ASIC_S,
    UA_SIGNATURE_FORMAT_CADES, UA_SIGNATURE_FORMAT_XADES, UA_SIGNATURE_HASH_DSTU7564, UA_SIGNATURE_HASH_GOST34311,
    UA_SIGNATURE_LEVEL_B, UA_SIGNATURE_LEVEL_LT, UA_SIGNATURE_LEVEL_T, UaBuffer, UaBytes, UaCurve, UaCurveBasis,
    UaKeyStoreRequest, UaNamedBytes, UaSignatureFormat, UaSignatureHash, UaSignatureLevel, UaSigningOptions,
};
use crate::errors::OperationFailure;
use crate::models::simple_types::{CurveBasis, SignatureFormat, SignatureHash};
use crate::models::{KeyStoreRequest, NamedCurve, SigningOptions};

/// The alias of a new key when the caller names none, as `ua-sign keygen` names it.
const DEFAULT_ALIAS: &str = "key";

/// The bytes of `bytes`; NULL with a zero length is empty.
///
/// # Safety
/// A non-NULL `data` points to `len` readable bytes that outlive the call.
pub unsafe fn read_bytes<'a>(bytes: UaBytes, what: &str) -> Result<&'a [u8], OperationFailure> {
    if bytes.data.is_null() {
        if bytes.len == 0 {
            return Ok(&[]);
        }
        return Err(OperationFailure::invalid_argument(format!(
            "{what} is NULL with a length of {}.",
            bytes.len
        )));
    }
    // SAFETY: the caller lends `len` bytes at `data`.
    Ok(unsafe { slice::from_raw_parts(bytes.data, bytes.len) })
}

/// The bytes of `bytes`, absent when `data` is NULL.
///
/// # Safety
/// As [`read_bytes`].
pub unsafe fn read_optional_bytes<'a>(bytes: UaBytes) -> Option<&'a [u8]> {
    if bytes.data.is_null() {
        return None;
    }
    // SAFETY: the caller lends `len` bytes at `data`.
    Some(unsafe { slice::from_raw_parts(bytes.data, bytes.len) })
}

/// The UTF-8 text at `text`.
///
/// # Safety
/// A non-NULL `text` points to a NUL-terminated string that outlives the call.
pub unsafe fn read_text<'a>(text: *const c_char, what: &str) -> Result<&'a str, OperationFailure> {
    // SAFETY: as the caller promises.
    match unsafe { read_optional_text(text, what) }? {
        Some(text) => Ok(text),
        None => Err(OperationFailure::invalid_argument(format!("{what} is NULL."))),
    }
}

/// The UTF-8 text at `text`, absent when NULL.
///
/// # Safety
/// As [`read_text`].
pub unsafe fn read_optional_text<'a>(text: *const c_char, what: &str) -> Result<Option<&'a str>, OperationFailure> {
    if text.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller lends a NUL-terminated string.
    let text = unsafe { CStr::from_ptr(text) };
    match text.to_str() {
        Ok(text) => Ok(Some(text)),
        Err(_) => Err(OperationFailure::invalid_argument(format!("{what} is not UTF-8."))),
    }
}

/// The `count` byte strings at `items`.
///
/// # Safety
/// A non-NULL `items` points to `count` `UaBytes`, each valid as [`read_bytes`] wants.
pub unsafe fn read_bytes_list(
    items: *const UaBytes,
    count: usize,
    what: &str,
) -> Result<Vec<Vec<u8>>, OperationFailure> {
    // SAFETY: as the caller promises.
    let items = unsafe { read_array(items, count, what) }?;
    // SAFETY: each item is valid as read_bytes wants.
    items
        .iter()
        .map(|&item| Ok(unsafe { read_bytes(item, what) }?.to_vec()))
        .collect()
}

/// The `count` named files at `items`.
///
/// # Safety
/// A non-NULL `items` points to `count` `UaNamedBytes`, each with a valid name and content.
pub unsafe fn read_files(
    items: *const UaNamedBytes,
    count: usize,
    what: &str,
) -> Result<Vec<SignedFile>, OperationFailure> {
    // SAFETY: as the caller promises.
    let items = unsafe { read_array(items, count, what) }?;
    let mut files = Vec::with_capacity(items.len());
    for item in items {
        // SAFETY: each item has a valid name and content.
        let name = unsafe { read_text(item.name, what) }?;
        let content = unsafe { read_bytes(item.content, what) }?;
        files.push(SignedFile {
            name: name.to_owned(),
            content: content.to_vec(),
        });
    }
    Ok(files)
}

/// The curve of `curve`.
pub fn read_curve(curve: UaCurve) -> Result<NamedCurve, OperationFailure> {
    let basis = match curve.basis {
        UA_CURVE_BASIS_POLYNOMIAL => CurveBasis::Polynomial,
        UA_CURVE_BASIS_OPTIMAL_NORMAL => CurveBasis::OptimalNormal,
        UaCurveBasis(other) => {
            return Err(OperationFailure::invalid_argument(format!(
                "Unknown curve basis {other}."
            )));
        }
    };
    Ok(NamedCurve { basis, m: curve.m })
}

/// The options at `options`.
///
/// # Safety
/// `options` is NULL or points to a `UaSigningOptions` whose URLs are NULL or NUL-terminated.
pub unsafe fn read_signing_options(options: *const UaSigningOptions) -> Result<SigningOptions, OperationFailure> {
    if options.is_null() {
        return Err(OperationFailure::invalid_argument("The signing options are NULL."));
    }
    // SAFETY: a non-NULL pointer to the options.
    let options = unsafe { &*options };
    Ok(SigningOptions {
        format: read_signature_format(options.format)?,
        level: read_signature_level(options.level)?,
        hash: read_signature_hash(options.hash)?,
        is_detached: options.is_detached,
        has_content_time_stamp: options.has_content_time_stamp,
        // SAFETY: the URLs are NULL or NUL-terminated.
        tsa_url: unsafe { read_optional_text(options.tsa_url, "The TSA URL") }?.map(str::to_owned),
        ocsp_url: unsafe { read_optional_text(options.ocsp_url, "The OCSP URL") }?.map(str::to_owned),
    })
}

/// The key store request at `request` with `password`.
///
/// # Safety
/// `request` is NULL or points to a `UaKeyStoreRequest` whose strings are NULL or NUL-terminated.
pub unsafe fn read_key_store_request(
    request: *const UaKeyStoreRequest,
    password: &str,
) -> Result<KeyStoreRequest, OperationFailure> {
    if request.is_null() {
        return Err(OperationFailure::invalid_argument("The key store request is NULL."));
    }
    // SAFETY: a non-NULL pointer to the request.
    let request = unsafe { &*request };
    // SAFETY: the strings are NULL or NUL-terminated.
    let subject = unsafe { read_text(request.subject, "The subject") }?;
    let alias = match unsafe { read_optional_text(request.alias, "The alias") }? {
        Some(alias) => alias,
        None => DEFAULT_ALIAS,
    };
    Ok(KeyStoreRequest {
        subject: subject.to_owned(),
        alias: alias.to_owned(),
        m: request.m,
        validity_days: request.validity_days,
        signature_hash: read_signature_hash(request.signature_hash)?,
        password: password.to_owned(),
    })
}

/// Hands `bytes` to the caller at `target`.
///
/// # Safety
/// `target` is NULL or points to a writable `UaBuffer`.
pub unsafe fn write_buffer(target: *mut UaBuffer, bytes: Vec<u8>) -> Result<(), OperationFailure> {
    if target.is_null() {
        return Err(OperationFailure::invalid_argument("An output buffer is NULL."));
    }
    // SAFETY: a non-NULL pointer to a writable UaBuffer.
    unsafe { target.write(into_buffer(bytes)) };
    Ok(())
}

/// Writes `value` at `target`.
///
/// # Safety
/// `target` is NULL or points to a writable `bool`.
pub unsafe fn write_flag(target: *mut bool, value: bool) -> Result<(), OperationFailure> {
    if target.is_null() {
        return Err(OperationFailure::invalid_argument("An output flag is NULL."));
    }
    // SAFETY: a non-NULL pointer to a writable bool.
    unsafe { target.write(value) };
    Ok(())
}

/// The buffer owning `bytes`; `release_buffer` takes it back.
pub fn into_buffer(bytes: Vec<u8>) -> UaBuffer {
    if bytes.is_empty() {
        return UaBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
    }
    let bytes = Box::into_raw(bytes.into_boxed_slice());
    UaBuffer {
        data: bytes.cast::<u8>(),
        len: bytes.len(),
    }
}

/// Takes back a buffer made by `into_buffer`.
///
/// # Safety
/// `buffer` came from `into_buffer` and is released once.
pub unsafe fn release_buffer(buffer: UaBuffer) {
    if buffer.data.is_null() {
        return;
    }
    let bytes = ptr::slice_from_raw_parts_mut(buffer.data, buffer.len);
    // SAFETY: the slice was boxed by into_buffer with this length.
    drop(unsafe { Box::from_raw(bytes) });
}

// The `count` items at `items`; NULL is no items when `count` is 0.
unsafe fn read_array<'a, T>(items: *const T, count: usize, what: &str) -> Result<&'a [T], OperationFailure> {
    if items.is_null() {
        if count == 0 {
            return Ok(&[]);
        }
        return Err(OperationFailure::invalid_argument(format!(
            "{what} is NULL with a count of {count}."
        )));
    }
    // SAFETY: the caller lends `count` items at `items`.
    Ok(unsafe { slice::from_raw_parts(items, count) })
}

fn read_signature_format(format: UaSignatureFormat) -> Result<SignatureFormat, OperationFailure> {
    match format {
        UA_SIGNATURE_FORMAT_CADES => Ok(SignatureFormat::Cades),
        UA_SIGNATURE_FORMAT_XADES => Ok(SignatureFormat::Xades),
        UA_SIGNATURE_FORMAT_ASIC_S => Ok(SignatureFormat::AsicS),
        UA_SIGNATURE_FORMAT_ASIC_E => Ok(SignatureFormat::AsicE),
        UaSignatureFormat(other) => Err(OperationFailure::invalid_argument(format!(
            "Unknown signature format {other}."
        ))),
    }
}

fn read_signature_level(level: UaSignatureLevel) -> Result<SignatureLevel, OperationFailure> {
    match level {
        UA_SIGNATURE_LEVEL_B => Ok(SignatureLevel::B),
        UA_SIGNATURE_LEVEL_T => Ok(SignatureLevel::T),
        UA_SIGNATURE_LEVEL_LT => Ok(SignatureLevel::LT),
        UaSignatureLevel(other) => Err(OperationFailure::invalid_argument(format!(
            "Unknown signature level {other}."
        ))),
    }
}

fn read_signature_hash(hash: UaSignatureHash) -> Result<SignatureHash, OperationFailure> {
    match hash {
        UA_SIGNATURE_HASH_DSTU7564 => Ok(SignatureHash::Dstu7564),
        UA_SIGNATURE_HASH_GOST34311 => Ok(SignatureHash::Gost34311),
        UaSignatureHash(other) => Err(OperationFailure::invalid_argument(format!(
            "Unknown signature hash {other}."
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bytes_are_empty_with_a_zero_length_and_refused_otherwise() {
        let empty = UaBytes {
            data: ptr::null(),
            len: 0,
        };
        let broken = UaBytes {
            data: ptr::null(),
            len: 3,
        };
        assert_eq!(unsafe { read_bytes(empty, "The data") }.unwrap(), b"");
        assert!(unsafe { read_bytes(broken, "The data") }.is_err());
        assert_eq!(unsafe { read_optional_bytes(empty) }, None);
    }

    #[test]
    fn a_buffer_hands_out_the_bytes_and_comes_back() {
        let buffer = into_buffer(vec![1, 2, 3]);
        assert_eq!(unsafe { slice::from_raw_parts(buffer.data, buffer.len) }, [1, 2, 3]);
        unsafe { release_buffer(buffer) };
        let empty = into_buffer(Vec::new());
        assert!(empty.data.is_null());
        unsafe { release_buffer(empty) };
    }

    #[test]
    fn text_must_be_utf8() {
        let invalid = [0xFFu8, 0];
        assert!(unsafe { read_text(invalid.as_ptr().cast(), "The name") }.is_err());
        assert!(unsafe { read_text(ptr::null(), "The name") }.is_err());
        assert_eq!(unsafe { read_text(c"name".as_ptr(), "The name") }.unwrap(), "name");
    }

    #[test]
    fn an_unknown_enumeration_value_is_refused() {
        let curve = UaCurve {
            basis: UaCurveBasis(7),
            m: 257,
        };
        assert!(read_curve(curve).is_err());
    }
}
