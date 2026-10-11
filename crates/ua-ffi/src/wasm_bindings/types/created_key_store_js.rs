use wasm_bindgen::prelude::wasm_bindgen;

/// A key store made by `createKeyStore` and the certificate of its key.
#[wasm_bindgen(js_name = CreatedKeyStore, getter_with_clone)]
#[derive(Debug, Clone)]
pub struct CreatedKeyStoreJs {
    /// The JKS bytes.
    #[wasm_bindgen(js_name = keyStore)]
    pub key_store: Vec<u8>,
    /// The self-signed certificate, DER.
    pub certificate: Vec<u8>,
}
