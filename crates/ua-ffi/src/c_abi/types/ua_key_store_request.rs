use std::ffi::c_char;

use crate::c_abi::types::UaSignatureHash;

/// A new key store with one DSTU 4145 key on a curve of table Г.1 and its self-signed certificate.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UaKeyStoreRequest {
    /// The subject, e.g. "CN=Name,O=Organization,C=UA".
    pub subject: *const c_char,
    /// The alias of the key entry; NULL: "key".
    pub alias: *const c_char,
    /// The degree m of the curve of table Г.1; 257 is the one of the national PKI.
    pub m: u32,
    /// How many days the certificate is valid.
    pub validity_days: u32,
    /// The hash the certificate is signed over.
    pub signature_hash: UaSignatureHash,
}
