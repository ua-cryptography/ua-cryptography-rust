use std::fmt;

use ua_cryptography_der::DerError;

use crate::errors::CertificateError;

/// Why bytes are not a usable OCSP response (RFC 6960, 4.2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcspError {
    /// The DER is not the structure expected.
    Der(DerError),
    /// The responder answered with a status other than successful.
    Refused {
        /// The OCSPResponseStatus.
        status: u8,
    },
    /// The response is not id-pkix-ocsp-basic.
    UnsupportedResponseType {
        /// The response type OID.
        oid: String,
    },
    /// A certificate inside the response is not readable.
    Certificate(CertificateError),
}

impl fmt::Display for OcspError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Der(error) => write!(formatter, "Invalid OCSP response: {error}."),
            Self::Refused { status } => write!(
                formatter,
                "The OCSP responder returned status {status} ({}).",
                status_name(*status)
            ),
            Self::UnsupportedResponseType { oid } => write!(formatter, "Unsupported OCSP response type {oid}."),
            Self::Certificate(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for OcspError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Der(error) => Some(error),
            Self::Certificate(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DerError> for OcspError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<CertificateError> for OcspError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

// OCSPResponseStatus (RFC 6960, 4.2.1); 4 is not used.
fn status_name(status: u8) -> &'static str {
    match status {
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => "unknown",
    }
}
