//! DSTU 7624:2014 "Kalyna" and its modes. `blockBits` is 128, 256 or 512; the key is one or two blocks long.

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::js_exports::to_js_error;
use ua_cryptography_operations::operations::dstu7624;

/// Encrypts one block.
#[wasm_bindgen(js_name = dstu7624EncryptBlock)]
pub fn dstu7624_encrypt_block(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    block: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::encrypt_block(block_bits, key, block).map_err(to_js_error)
}

/// Decrypts one block.
#[wasm_bindgen(js_name = dstu7624DecryptBlock)]
pub fn dstu7624_decrypt_block(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    block: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::decrypt_block(block_bits, key, block).map_err(to_js_error)
}

/// ECB ("простої заміни"): encrypts whole blocks.
#[wasm_bindgen(js_name = dstu7624EcbEncrypt)]
pub fn dstu7624_ecb_encrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::ecb_encrypt(block_bits, key, data).map_err(to_js_error)
}

/// ECB: decrypts whole blocks.
#[wasm_bindgen(js_name = dstu7624EcbDecrypt)]
pub fn dstu7624_ecb_decrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::ecb_decrypt(block_bits, key, data).map_err(to_js_error)
}

/// CBC ("простої заміни з зачепленням"): whole blocks, an IV of one block.
#[wasm_bindgen(js_name = dstu7624CbcEncrypt)]
pub fn dstu7624_cbc_encrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::cbc_encrypt(block_bits, key, iv, data).map_err(to_js_error)
}

/// CBC decryption.
#[wasm_bindgen(js_name = dstu7624CbcDecrypt)]
pub fn dstu7624_cbc_decrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::cbc_decrypt(block_bits, key, iv, data).map_err(to_js_error)
}

/// CFB with a segment of `segmentBits` (one block when absent); any length.
#[wasm_bindgen(js_name = dstu7624CfbEncrypt)]
pub fn dstu7624_cfb_encrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    #[wasm_bindgen(js_name = segmentBits)] segment_bits: Option<u32>,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::cfb_encrypt(block_bits, key, segment_bits, iv, data).map_err(to_js_error)
}

/// CFB decryption.
#[wasm_bindgen(js_name = dstu7624CfbDecrypt)]
pub fn dstu7624_cfb_decrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    #[wasm_bindgen(js_name = segmentBits)] segment_bits: Option<u32>,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::cfb_decrypt(block_bits, key, segment_bits, iv, data).map_err(to_js_error)
}

/// OFB with a segment of `segmentBits` (one block when absent): encrypts and decrypts alike.
#[wasm_bindgen(js_name = dstu7624OfbApplyGamma)]
pub fn dstu7624_ofb_apply_gamma(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    #[wasm_bindgen(js_name = segmentBits)] segment_bits: Option<u32>,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::ofb_apply_gamma(block_bits, key, segment_bits, iv, data).map_err(to_js_error)
}

/// CTR ("гамування"): encrypts and decrypts alike; any length.
#[wasm_bindgen(js_name = dstu7624CtrApplyGamma)]
pub fn dstu7624_ctr_apply_gamma(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::ctr_apply_gamma(block_bits, key, iv, data).map_err(to_js_error)
}

/// CMAC ("вироблення імітовставки") of `macBits` over a non-empty whole number of blocks.
#[wasm_bindgen(js_name = dstu7624CmacCalculateMac)]
pub fn dstu7624_cmac_calculate_mac(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    #[wasm_bindgen(js_name = macBits)] mac_bits: u32,
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::cmac_calculate_mac(block_bits, key, mac_bits, data).map_err(to_js_error)
}

/// CCM: ciphertext ‖ tag of `macBits`; the length field `nb` is 4, 6 or 8 bytes (4 when absent).
#[wasm_bindgen(js_name = dstu7624CcmEncrypt)]
pub fn dstu7624_ccm_encrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    nb: Option<u32>,
    nonce: &[u8],
    #[wasm_bindgen(js_name = associatedData)] associated_data: &[u8],
    #[wasm_bindgen(js_name = plainText)] plain_text: &[u8],
    #[wasm_bindgen(js_name = macBits)] mac_bits: u32,
) -> Result<Vec<u8>, JsValue> {
    dstu7624::ccm_encrypt(block_bits, key, nb, nonce, associated_data, plain_text, mac_bits).map_err(to_js_error)
}

/// CCM: verifies the tag and decrypts; throws AuthenticationFailed on a forged tag.
#[wasm_bindgen(js_name = dstu7624CcmDecrypt)]
pub fn dstu7624_ccm_decrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    nb: Option<u32>,
    nonce: &[u8],
    #[wasm_bindgen(js_name = associatedData)] associated_data: &[u8],
    #[wasm_bindgen(js_name = cipherText)] cipher_text: &[u8],
    #[wasm_bindgen(js_name = macBits)] mac_bits: u32,
) -> Result<Vec<u8>, JsValue> {
    dstu7624::ccm_decrypt(block_bits, key, nb, nonce, associated_data, cipher_text, mac_bits).map_err(to_js_error)
}

/// GCM: ciphertext ‖ tag of `macBits`; the nonce is at most a block.
#[wasm_bindgen(js_name = dstu7624GcmEncrypt)]
pub fn dstu7624_gcm_encrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    nonce: &[u8],
    #[wasm_bindgen(js_name = associatedData)] associated_data: &[u8],
    #[wasm_bindgen(js_name = plainText)] plain_text: &[u8],
    #[wasm_bindgen(js_name = macBits)] mac_bits: u32,
) -> Result<Vec<u8>, JsValue> {
    dstu7624::gcm_encrypt(block_bits, key, nonce, associated_data, plain_text, mac_bits).map_err(to_js_error)
}

/// GCM: verifies the tag and decrypts; throws AuthenticationFailed on a forged tag.
#[wasm_bindgen(js_name = dstu7624GcmDecrypt)]
pub fn dstu7624_gcm_decrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    nonce: &[u8],
    #[wasm_bindgen(js_name = associatedData)] associated_data: &[u8],
    #[wasm_bindgen(js_name = cipherText)] cipher_text: &[u8],
    #[wasm_bindgen(js_name = macBits)] mac_bits: u32,
) -> Result<Vec<u8>, JsValue> {
    dstu7624::gcm_decrypt(block_bits, key, nonce, associated_data, cipher_text, mac_bits).map_err(to_js_error)
}

/// GMAC of `macBits` over `data` under `nonce`.
#[wasm_bindgen(js_name = dstu7624GmacCalculateMac)]
pub fn dstu7624_gmac_calculate_mac(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    #[wasm_bindgen(js_name = macBits)] mac_bits: u32,
) -> Result<Vec<u8>, JsValue> {
    dstu7624::gmac_calculate_mac(block_bits, key, nonce, data, mac_bits).map_err(to_js_error)
}

/// XTS ("індексована заміна"): whole blocks under the tweak IV of one block.
#[wasm_bindgen(js_name = dstu7624XtsEncrypt)]
pub fn dstu7624_xts_encrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::xts_encrypt(block_bits, key, iv, data).map_err(to_js_error)
}

/// XTS decryption.
#[wasm_bindgen(js_name = dstu7624XtsDecrypt)]
pub fn dstu7624_xts_decrypt(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::xts_decrypt(block_bits, key, iv, data).map_err(to_js_error)
}

/// KW ("захист ключів"): wraps a non-empty whole number of blocks into one block more.
#[wasm_bindgen(js_name = dstu7624WrapKey)]
pub fn dstu7624_wrap_key(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::wrap_key(block_bits, key, data).map_err(to_js_error)
}

/// KW: unwraps and checks the integrity block; throws AuthenticationFailed when it is not zero.
#[wasm_bindgen(js_name = dstu7624UnwrapKey)]
pub fn dstu7624_unwrap_key(
    #[wasm_bindgen(js_name = blockBits)] block_bits: u32,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu7624::unwrap_key(block_bits, key, data).map_err(to_js_error)
}
