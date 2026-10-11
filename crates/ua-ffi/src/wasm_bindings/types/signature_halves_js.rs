use wasm_bindgen::prelude::wasm_bindgen;

/// The integers r and s of a DSTU 4145 signature (5.11), big-endian.
#[wasm_bindgen(js_name = SignatureHalves, getter_with_clone)]
#[derive(Debug, Clone)]
pub struct SignatureHalvesJs {
    /// r.
    pub r: Vec<u8>,
    /// s.
    pub s: Vec<u8>,
}
