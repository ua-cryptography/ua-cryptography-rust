use std::fmt;

use ua_cryptography_der::{DerError, PemError};

use crate::errors::CertificateError;

/// Why bytes are not a CMS ContentInfo with SignedData (RFC 5652, 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmsError {
    /// The data is neither DER nor PEM nor base64.
    Pem(PemError),
    /// The DER is not the structure expected.
    Der(DerError),
    /// The ContentInfo holds another content type.
    NotSignedData {
        /// The content type found.
        content_type: String,
    },
    /// An embedded certificate is not readable.
    Certificate(CertificateError),
}

impl fmt::Display for CmsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pem(error) => write!(formatter, "Not a CMS signature: {error}."),
            Self::Der(error) => write!(formatter, "Invalid CMS structure: {error}."),
            Self::NotSignedData { .. } => write!(formatter, "The CMS ContentInfo is not SignedData."),
            Self::Certificate(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CmsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pem(error) => Some(error),
            Self::Der(error) => Some(error),
            Self::Certificate(error) => Some(error),
            Self::NotSignedData { .. } => None,
        }
    }
}

impl From<DerError> for CmsError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<PemError> for CmsError {
    fn from(error: PemError) -> Self {
        Self::Pem(error)
    }
}

impl From<CertificateError> for CmsError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}
