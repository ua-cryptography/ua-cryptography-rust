use crate::ocsp::{OcspResponse, OcspSingleResponse};
use crate::x509::Certificate;

/// The status of a certificate on a path, established from an authorized OCSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationStatus {
    /// The name of the path, e.g. "signer".
    pub path: String,
    /// The certificate the status is about.
    pub certificate: Certificate,
    /// The OCSP response.
    pub response: OcspResponse,
    /// The single response about the certificate.
    pub status: OcspSingleResponse,
    /// The responder's certificate.
    pub responder: Certificate,
    /// True when the response was asked online rather than found in the signature.
    pub is_online: bool,
}
