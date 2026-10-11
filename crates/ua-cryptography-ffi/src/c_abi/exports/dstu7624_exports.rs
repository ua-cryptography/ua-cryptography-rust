//! DSTU 7624:2014 "Kalyna" and its modes. `block_bits` is 128, 256 or 512; `key` is one or two blocks long
//! (128/128, 128/256, 256/256, 256/512, 512/512).

use crate::c_abi::call_guard::run_call;
use crate::c_abi::marshalling::{read_bytes, write_buffer};
use crate::c_abi::types::{UaBuffer, UaBytes, UaStatus};
use ua_cryptography_operations::operations::dstu7624;

/// Encrypts one block.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_encrypt_block(
    block_bits: u32,
    key: UaBytes,
    block: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output =
                dstu7624::encrypt_block(block_bits, read_bytes(key, "The key")?, read_bytes(block, "The block")?)?;
            write_buffer(result, output)
        })
    }
}

/// Decrypts one block.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_decrypt_block(
    block_bits: u32,
    key: UaBytes,
    block: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output =
                dstu7624::decrypt_block(block_bits, read_bytes(key, "The key")?, read_bytes(block, "The block")?)?;
            write_buffer(result, output)
        })
    }
}

/// ECB ("простої заміни"): encrypts whole blocks.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_ecb_encrypt(
    block_bits: u32,
    key: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::ecb_encrypt(block_bits, read_bytes(key, "The key")?, read_bytes(data, "The data")?)?;
            write_buffer(result, output)
        })
    }
}

/// ECB: decrypts whole blocks.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_ecb_decrypt(
    block_bits: u32,
    key: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::ecb_decrypt(block_bits, read_bytes(key, "The key")?, read_bytes(data, "The data")?)?;
            write_buffer(result, output)
        })
    }
}

/// CBC ("простої заміни з зачепленням"): whole blocks, an IV of one block.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_cbc_encrypt(
    block_bits: u32,
    key: UaBytes,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::cbc_encrypt(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// CBC decryption.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_cbc_decrypt(
    block_bits: u32,
    key: UaBytes,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::cbc_decrypt(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// CFB with a segment of `segment_bits` (0: one block); any length; a short IV is right-aligned.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_cfb_encrypt(
    block_bits: u32,
    key: UaBytes,
    segment_bits: u32,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::cfb_encrypt(
                block_bits,
                read_bytes(key, "The key")?,
                optional_number(segment_bits),
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// CFB decryption; `segment_bits` 0 is one block.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_cfb_decrypt(
    block_bits: u32,
    key: UaBytes,
    segment_bits: u32,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::cfb_decrypt(
                block_bits,
                read_bytes(key, "The key")?,
                optional_number(segment_bits),
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// OFB with a segment of `segment_bits` (0: one block): encrypts and decrypts alike.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_ofb_apply_gamma(
    block_bits: u32,
    key: UaBytes,
    segment_bits: u32,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::ofb_apply_gamma(
                block_bits,
                read_bytes(key, "The key")?,
                optional_number(segment_bits),
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// CTR ("гамування"): encrypts and decrypts alike; any length.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_ctr_apply_gamma(
    block_bits: u32,
    key: UaBytes,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::ctr_apply_gamma(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// CMAC ("вироблення імітовставки") of `mac_bits` over a non-empty whole number of blocks.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_cmac_calculate_mac(
    block_bits: u32,
    key: UaBytes,
    mac_bits: u32,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::cmac_calculate_mac(
                block_bits,
                read_bytes(key, "The key")?,
                mac_bits,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// CCM: ciphertext ‖ tag of `mac_bits`; the length field `nb` is 4, 6 or 8 bytes (0: 4).
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_ccm_encrypt(
    block_bits: u32,
    key: UaBytes,
    nb: u32,
    nonce: UaBytes,
    associated_data: UaBytes,
    plain_text: UaBytes,
    mac_bits: u32,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::ccm_encrypt(
                block_bits,
                read_bytes(key, "The key")?,
                optional_number(nb),
                read_bytes(nonce, "The nonce")?,
                read_bytes(associated_data, "The associated data")?,
                read_bytes(plain_text, "The plaintext")?,
                mac_bits,
            )?;
            write_buffer(result, output)
        })
    }
}

/// CCM: verifies the tag of ciphertext ‖ tag and decrypts; `UA_STATUS_AUTHENTICATION_FAILED` on a forged tag.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_ccm_decrypt(
    block_bits: u32,
    key: UaBytes,
    nb: u32,
    nonce: UaBytes,
    associated_data: UaBytes,
    cipher_text: UaBytes,
    mac_bits: u32,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::ccm_decrypt(
                block_bits,
                read_bytes(key, "The key")?,
                optional_number(nb),
                read_bytes(nonce, "The nonce")?,
                read_bytes(associated_data, "The associated data")?,
                read_bytes(cipher_text, "The ciphertext")?,
                mac_bits,
            )?;
            write_buffer(result, output)
        })
    }
}

/// GCM: ciphertext ‖ tag of `mac_bits`; the nonce is at most a block.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_gcm_encrypt(
    block_bits: u32,
    key: UaBytes,
    nonce: UaBytes,
    associated_data: UaBytes,
    plain_text: UaBytes,
    mac_bits: u32,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::gcm_encrypt(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(nonce, "The nonce")?,
                read_bytes(associated_data, "The associated data")?,
                read_bytes(plain_text, "The plaintext")?,
                mac_bits,
            )?;
            write_buffer(result, output)
        })
    }
}

/// GCM: verifies the tag of ciphertext ‖ tag and decrypts; `UA_STATUS_AUTHENTICATION_FAILED` on a forged tag.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_gcm_decrypt(
    block_bits: u32,
    key: UaBytes,
    nonce: UaBytes,
    associated_data: UaBytes,
    cipher_text: UaBytes,
    mac_bits: u32,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::gcm_decrypt(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(nonce, "The nonce")?,
                read_bytes(associated_data, "The associated data")?,
                read_bytes(cipher_text, "The ciphertext")?,
                mac_bits,
            )?;
            write_buffer(result, output)
        })
    }
}

/// GMAC of `mac_bits` over `data` under `nonce`.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_gmac_calculate_mac(
    block_bits: u32,
    key: UaBytes,
    nonce: UaBytes,
    data: UaBytes,
    mac_bits: u32,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::gmac_calculate_mac(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(nonce, "The nonce")?,
                read_bytes(data, "The data")?,
                mac_bits,
            )?;
            write_buffer(result, output)
        })
    }
}

/// XTS ("індексована заміна"): whole blocks under the tweak IV of one block.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_xts_encrypt(
    block_bits: u32,
    key: UaBytes,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::xts_encrypt(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// XTS decryption.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_xts_decrypt(
    block_bits: u32,
    key: UaBytes,
    iv: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::xts_decrypt(
                block_bits,
                read_bytes(key, "The key")?,
                read_bytes(iv, "The IV")?,
                read_bytes(data, "The data")?,
            )?;
            write_buffer(result, output)
        })
    }
}

/// KW ("захист ключів"): wraps a non-empty whole number of blocks into one block more.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_wrap_key(
    block_bits: u32,
    key: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::wrap_key(block_bits, read_bytes(key, "The key")?, read_bytes(data, "The data")?)?;
            write_buffer(result, output)
        })
    }
}

/// KW: unwraps and checks the integrity block; `UA_STATUS_AUTHENTICATION_FAILED` when it is not zero.
///
/// # Safety
/// Every pointer is NULL or valid as its type says; outputs are written only on `UA_STATUS_OK`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ua_dstu7624_unwrap_key(
    block_bits: u32,
    key: UaBytes,
    data: UaBytes,
    result: *mut UaBuffer,
    error_message: *mut UaBuffer,
) -> UaStatus {
    unsafe {
        run_call(error_message, || {
            let output = dstu7624::unwrap_key(block_bits, read_bytes(key, "The key")?, read_bytes(data, "The data")?)?;
            write_buffer(result, output)
        })
    }
}

// 0 stands for the mode's default (a segment of one block, Nb = 4), as C has no absent integer.
fn optional_number(value: u32) -> Option<u32> {
    (value != 0).then_some(value)
}
