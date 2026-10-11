use wasm_bindgen::prelude::wasm_bindgen;

/// A DSTU 4145 key pair: d big-endian, Q compressed (6.9) big-endian.
#[wasm_bindgen(js_name = KeyPair, getter_with_clone)]
#[derive(Clone)]
pub struct KeyPairJs {
    /// The private key d.
    #[wasm_bindgen(js_name = privateKey)]
    pub private_key: Vec<u8>,
    /// The compressed public key Q = −dP.
    #[wasm_bindgen(js_name = publicKey)]
    pub public_key: Vec<u8>,
}
