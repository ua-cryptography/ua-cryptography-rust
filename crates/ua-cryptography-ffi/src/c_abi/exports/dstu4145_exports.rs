//! DSTU 4145-2002 on the recommended curves of Appendix Г. Integers are big-endian: d (⌈L(n) / 8⌉ bytes when
//! generated), e, r, s and the signature D = S‖R of 5.10; Q is compressed (6.9), ⌈m / 8⌉ bytes; a hash code is
//! most significant byte first (5.9). The national PKI reverses its digests and stores D reversed.

use crate::c_abi::call_guard::run_call;
use crate::c_abi::marshalling::{read_bytes, read_curve, read_optional_bytes, write_buffer, write_flag};
use crate::c_abi::types::{UaBuffer, UaBytes, UaCurve, UaStatus};
use ua_cryptography_operations::operations::dstu4145;

/// Section 9: a random private key d (from the OS generator) and the compressed public key Q = −dP.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_generate_key_pair(
    curve: UaCurve,
    private_key: *mut UaBuffer,
    public_key: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let key_pair = dstu4145::generate_key_pair(read_curve(curve)?)?;
            write_buffer(private_key, key_pair.private_key)?;
            write_buffer(public_key, key_pair.public_key)
        })
    }
}

/// 9.2: the compressed Q = −dP of the private key d.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_calculate_public_key(
    curve: UaCurve,
    private_key: UaBytes,
    public_key: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let q = dstu4145::calculate_public_key(read_curve(curve)?, read_bytes(private_key, "The private key")?)?;
            write_buffer(public_key, q)
        })
    }
}

/// 6.10 and 10.1: `UA_STATUS_OK` when the compressed key is a point of order n; otherwise
/// `UA_STATUS_INVALID_ARGUMENT` with the failed clause.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_validate_public_key(
    curve: UaCurve,
    public_key: UaBytes,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            dstu4145::validate_public_key(read_curve(curve)?, read_bytes(public_key, "The public key")?)
        })
    }
}

/// Section 12: signs a hash code with a random presignature; `signature_bits` is L_D (0: the shortest, 2 L(n)
/// rounded up to 16).
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_sign_hash(
    curve: UaCurve,
    private_key: UaBytes,
    hash: UaBytes,
    signature_bits: u32,
    signature: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let result = dstu4145::sign_hash(
                read_curve(curve)?,
                read_bytes(private_key, "The private key")?,
                read_bytes(hash, "The hash")?,
                optional_number(signature_bits),
            )?;
            write_buffer(signature, result)
        })
    }
}

/// Section 12 with the given secret e of the presignature (section 11): the same e gives the same signature;
/// `UA_STATUS_INVALID_ARGUMENT` when e is out of range or yields r = 0 or s = 0. `signature_bits` 0: the shortest.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_sign_hash_with_presignature(
    curve: UaCurve,
    private_key: UaBytes,
    hash: UaBytes,
    e: UaBytes,
    signature_bits: u32,
    signature: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let result = dstu4145::sign_hash_with_presignature(
                read_curve(curve)?,
                read_bytes(private_key, "The private key")?,
                read_bytes(hash, "The hash")?,
                read_bytes(e, "e")?,
                optional_number(signature_bits),
            )?;
            write_buffer(signature, result)
        })
    }
}

/// Section 13: writes whether D is a signature of the hash code under the compressed public key.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_verify_hash(
    curve: UaCurve,
    public_key: UaBytes,
    hash: UaBytes,
    signature: UaBytes,
    is_valid: *mut bool,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let verdict = dstu4145::verify_hash(
                read_curve(curve)?,
                read_bytes(public_key, "The public key")?,
                read_bytes(hash, "The hash")?,
                read_bytes(signature, "The signature")?,
            )?;
            write_flag(is_valid, verdict)
        })
    }
}

/// Section 12 over H(T) by GOST 34.311 (6.2); `dke` is the 64-byte table, DKE No. 1 when NULL;
/// `signature_bits` 0: the shortest.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_sign_message(
    curve: UaCurve,
    private_key: UaBytes,
    message: UaBytes,
    dke: UaBytes,
    signature_bits: u32,
    signature: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let result = dstu4145::sign_message(
                read_curve(curve)?,
                read_bytes(private_key, "The private key")?,
                read_bytes(message, "The message")?,
                read_optional_bytes(dke),
                optional_number(signature_bits),
            )?;
            write_buffer(signature, result)
        })
    }
}

/// Section 13 over H(T) by GOST 34.311 (6.2); `dke` is the 64-byte table, DKE No. 1 when NULL.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_verify_message(
    curve: UaCurve,
    public_key: UaBytes,
    message: UaBytes,
    dke: UaBytes,
    signature: UaBytes,
    is_valid: *mut bool,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let verdict = dstu4145::verify_message(
                read_curve(curve)?,
                read_bytes(public_key, "The public key")?,
                read_bytes(message, "The message")?,
                read_optional_bytes(dke),
                read_bytes(signature, "The signature")?,
            )?;
            write_flag(is_valid, verdict)
        })
    }
}

/// 5.10: (r, s) → D = S‖R of `signature_bits` bits, a positive multiple of 16.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_encode_signature(
    r: UaBytes,
    s: UaBytes,
    signature_bits: u32,
    signature: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let result = dstu4145::encode_signature(read_bytes(r, "r")?, read_bytes(s, "s")?, signature_bits)?;
            write_buffer(signature, result)
        })
    }
}

/// 5.11: D → (r, s), each half of its bits, without leading zeros.
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_decode_signature(
    signature: UaBytes,
    r: *mut UaBuffer,
    s: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let halves = dstu4145::decode_signature(read_bytes(signature, "The signature")?)?;
            write_buffer(r, halves.r)?;
            write_buffer(s, halves.s)
        })
    }
}

/// Appendix А: `count` bytes of the generator on GOST 28147.
///
/// * `key` — the 32-byte key k
/// * `seed` — the 8-byte seed s
/// * `date_time` — D in .NET ticks (100 ns since 0001-01-01); NULL: now
/// * `dke` — the 64-byte table; NULL `data`: DKE No. 1
///
/// # Safety
/// As `ua_dstu4145_generate_key_pair`; `date_time` is NULL or readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu4145_generate_random_bytes(
    key: UaBytes,
    seed: UaBytes,
    date_time: *const u64,
    dke: UaBytes,
    count: usize,
    bytes: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let date_time = if date_time.is_null() {
                None
            } else {
                Some(date_time.read())
            };
            let result = dstu4145::generate_random_bytes(
                read_bytes(key, "The key")?,
                read_bytes(seed, "The seed")?,
                date_time,
                read_optional_bytes(dke),
                count,
            )?;
            write_buffer(bytes, result)
        })
    }
}

// 0 stands for the shortest signature, as C has no absent integer.
fn optional_number(value: u32) -> Option<u32> {
    (value != 0).then_some(value)
}
