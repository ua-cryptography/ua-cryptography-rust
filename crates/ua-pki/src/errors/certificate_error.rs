use std::fmt;

use ua_der::{DerError, PemError};

use crate::errors::CmsError;

/// Why bytes or a file are not an X.509 certificate (or a set of them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// The data is neither DER nor PEM.
    Pem(PemError),
    /// The DER is not a certificate structure (RFC 5280, 4.1).
    Der(DerError),
    /// A certificate bundle (.p7b/.p7c) is not a readable CMS structure.
    Bundle(Box<CmsError>),
    /// A certificate file cannot be read.
    Io {
        /// The path of the file.
        path: String,
        /// What the operating system reported.
        message: String,
    },
}

impl fmt::Display for CertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pem(error) => write!(formatter, "Not a certificate: {error}."),
            Self::Der(error) => write!(formatter, "Invalid certificate: {error}."),
            Self::Bundle(error) => write!(formatter, "Invalid certificate bundle: {error}"),
            Self::Io { path, message } => write!(formatter, "Cannot read {path}: {message}."),
        }
    }
}

impl std::error::Error for CertificateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Pem(error) => Some(error),
            Self::Der(error) => Some(error),
            Self::Bundle(error) => Some(error.as_ref()),
            Self::Io { .. } => None,
        }
    }
}

impl From<DerError> for CertificateError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<PemError> for CertificateError {
    fn from(error: PemError) -> Self {
        Self::Pem(error)
    }
}
