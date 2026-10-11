use std::fmt;

use crate::errors::KeyError;

/// Why a private key and a certificate chain do not make a signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningKeyError {
    /// The chain is empty: the signer's certificate is required.
    MissingCertificate,
    /// The private key is not the key of the first certificate.
    KeyMismatch,
    /// The first certificate's key is not a usable DSTU 4145 key.
    Key(KeyError),
}

impl fmt::Display for SigningKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCertificate => write!(formatter, "The signer's certificate is required."),
            Self::KeyMismatch => write!(formatter, "The private key does not match the certificate."),
            Self::Key(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SigningKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            _ => None,
        }
    }
}
