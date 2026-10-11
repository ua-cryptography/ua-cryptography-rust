use ua_pki::SignatureLevel;

use crate::models::simple_types::{SignatureFormat, SignatureHash};

/// How a signature is made, as the options of `ua-sign sign` say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningOptions {
    /// The format.
    pub format: SignatureFormat,
    /// B, T (+ time-stamp) or LT (+ certificates and OCSP responses).
    pub level: SignatureLevel,
    /// The hash of the signature.
    pub hash: SignatureHash,
    /// CAdES without the data.
    pub is_detached: bool,
    /// CAdES with a time-stamp of the data itself.
    pub has_content_time_stamp: bool,
    /// The time-stamping service; absent: the one the signer's certificate names.
    pub tsa_url: Option<String>,
    /// The OCSP responder for every certificate; absent: each certificate's own.
    pub ocsp_url: Option<String>,
}
