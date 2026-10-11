//! GOST 28147-89 in simple substitution mode over whole 64-bit blocks.

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::operations::gost28147;
use crate::wasm_bindings::js_inputs::to_js_error;

/// Encrypts whole 8-byte blocks under the 32-byte key; `dke` (64 bytes) defaults to DKE No. 1.
#[wasm_bindgen(js_name = gost28147Encrypt)]
pub fn gost28147_encrypt(key: &[u8], dke: Option<Vec<u8>>, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    gost28147::encrypt(key, dke.as_deref(), data).map_err(to_js_error)
}

/// Decrypts whole 8-byte blocks under the 32-byte key; `dke` (64 bytes) defaults to DKE No. 1.
#[wasm_bindgen(js_name = gost28147Decrypt)]
pub fn gost28147_decrypt(key: &[u8], dke: Option<Vec<u8>>, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    gost28147::decrypt(key, dke.as_deref(), data).map_err(to_js_error)
}
