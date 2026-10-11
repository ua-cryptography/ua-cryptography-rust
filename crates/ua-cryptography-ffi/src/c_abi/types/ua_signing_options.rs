use std::ffi::c_char;

use crate::c_abi::types::{UaSignatureFormat, UaSignatureHash, UaSignatureLevel};

/// How `ua_sign` signs.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UaSigningOptions {
    /// The format.
    pub format: UaSignatureFormat,
    /// B, T (asks the time-stamping service) or LT (also OCSP and caIssuers).
    pub level: UaSignatureLevel,
    /// The hash of the signature.
    pub hash: UaSignatureHash,
    /// CAdES without the data.
    pub is_detached: bool,
    /// CAdES and ASiC-S: also time-stamp the data itself.
    pub has_content_time_stamp: bool,
    /// The time-stamping service URL; NULL: the one the signer's certificate names.
    pub tsa_url: *const c_char,
    /// The OCSP responder URL for every certificate; NULL: each certificate's own.
    pub ocsp_url: *const c_char,
}
