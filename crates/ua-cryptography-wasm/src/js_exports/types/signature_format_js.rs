use wasm_bindgen::prelude::wasm_bindgen;

use ua_cryptography_operations::models::simple_types::SignatureFormat;

/// A signature format.
#[wasm_bindgen(js_name = SignatureFormat)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormatJs {
    /// CMS SignedData (.p7s), enveloped or detached; one file.
    Cades = 0,
    /// A detached XML signature with one reference per file (.xml).
    Xades = 1,
    /// A ZIP container with the file and a detached CAdES (.asics); one file.
    AsicS = 2,
    /// A ZIP container with the files and a XAdES signature (.asice).
    AsicE = 3,
}

impl From<SignatureFormatJs> for SignatureFormat {
    fn from(format: SignatureFormatJs) -> Self {
        match format {
            SignatureFormatJs::Cades => Self::Cades,
            SignatureFormatJs::Xades => Self::Xades,
            SignatureFormatJs::AsicS => Self::AsicS,
            SignatureFormatJs::AsicE => Self::AsicE,
        }
    }
}
