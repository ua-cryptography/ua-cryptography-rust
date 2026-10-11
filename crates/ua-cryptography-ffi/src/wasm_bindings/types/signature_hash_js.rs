use wasm_bindgen::prelude::wasm_bindgen;

use crate::models::simple_types::SignatureHash;

/// The hash of a PKI signature.
#[wasm_bindgen(js_name = SignatureHash)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureHashJs {
    /// DSTU 7564-256 (Kupyna), the hash of the current national PKI.
    Dstu7564 = 0,
    /// GOST 34.311-95 with the DKE of the key.
    Gost34311 = 1,
}

impl From<SignatureHashJs> for SignatureHash {
    fn from(hash: SignatureHashJs) -> Self {
        match hash {
            SignatureHashJs::Dstu7564 => Self::Dstu7564,
            SignatureHashJs::Gost34311 => Self::Gost34311,
        }
    }
}
