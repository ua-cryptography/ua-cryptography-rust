//! GOST 34.311-95 and DSTU 7564, one-shot and fed in parts.

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::operations::{StreamingHash, dstu7564, gost34311};
use crate::wasm_bindings::js_inputs::to_js_error;
use crate::wasm_bindings::types::HashStateJs;

/// GOST 34.311-95: 32 bytes, least significant first; `dke` (64 bytes) defaults to DKE No. 1, `initialValue`
/// (32 bytes) to zero.
#[wasm_bindgen(js_name = gost34311CalculateHash)]
pub fn gost34311_calculate_hash(
    data: &[u8],
    dke: Option<Vec<u8>>,
    #[wasm_bindgen(js_name = initialValue)] initial_value: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    gost34311::calculate_hash(data, dke.as_deref(), initial_value.as_deref()).map_err(to_js_error)
}

/// DSTU 7564 "Kupyna" of 256, 384 or 512 bits.
#[wasm_bindgen(js_name = dstu7564CalculateHash)]
pub fn dstu7564_calculate_hash(
    data: &[u8],
    #[wasm_bindgen(js_name = hashBits)] hash_bits: u32,
) -> Result<Vec<u8>, JsValue> {
    dstu7564::calculate_hash(data, hash_bits).map_err(to_js_error)
}

/// Begins GOST 34.311-95 of a message fed in parts.
#[wasm_bindgen(js_name = gost34311BeginHash)]
pub fn gost34311_begin_hash(
    dke: Option<Vec<u8>>,
    #[wasm_bindgen(js_name = initialValue)] initial_value: Option<Vec<u8>>,
) -> Result<HashStateJs, JsValue> {
    let hash = gost34311::create_hash(dke.as_deref(), initial_value.as_deref()).map_err(to_js_error)?;
    Ok(HashStateJs::new(StreamingHash::Gost34311(hash)))
}

/// Begins DSTU 7564 of 256, 384 or 512 bits of a message fed in parts.
#[wasm_bindgen(js_name = dstu7564BeginHash)]
pub fn dstu7564_begin_hash(#[wasm_bindgen(js_name = hashBits)] hash_bits: u32) -> Result<HashStateJs, JsValue> {
    let hash = dstu7564::create_hash(hash_bits).map_err(to_js_error)?;
    Ok(HashStateJs::new(StreamingHash::Dstu7564(hash)))
}
