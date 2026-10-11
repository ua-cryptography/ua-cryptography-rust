use ua_cryptography_pki::SignatureLevel;
use wasm_bindgen::prelude::wasm_bindgen;

/// A signature level; the browser build makes B only, T and LT need the network.
#[wasm_bindgen(js_name = SignatureLevel)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureLevelJs {
    /// The basic signature.
    B = 0,
    /// With a signature time-stamp.
    T = 1,
    /// With the CA certificates and OCSP responses.
    LT = 2,
}

impl From<SignatureLevelJs> for SignatureLevel {
    fn from(level: SignatureLevelJs) -> Self {
        match level {
            SignatureLevelJs::B => Self::B,
            SignatureLevelJs::T => Self::T,
            SignatureLevelJs::LT => Self::LT,
        }
    }
}
