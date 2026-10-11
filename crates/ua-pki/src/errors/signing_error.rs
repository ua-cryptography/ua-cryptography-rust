use std::fmt;

use crate::errors::{AlgorithmError, KeyError, ServiceError};
use crate::ocsp::OcspCertificateStatus;

/// Why a signature (a certificate, a CMS signer, CAdES, XAdES) is not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    /// The hash or signature algorithm is not one of the national PKI.
    Algorithm(AlgorithmError),
    /// The key cannot be written (its point has no compressed form).
    Key(KeyError),
    /// DSTU 4145 refuses to sign (an empty hash).
    Dstu4145(ua_dstu4145::SigningError),
    /// Nothing was given to sign.
    NothingToSign,
    /// Levels T and LT need a time-stamping service.
    NoTimeStampService,
    /// Level LT needs an OCSP service.
    NoOcspService,
    /// A service failed.
    Service(ServiceError),
    /// The signer's certification path ends at a certificate whose issuer is not available.
    IncompletePath {
        /// The common name (or the subject) of the last certificate found.
        top: String,
    },
    /// No OCSP responder is known for a certificate of the path.
    NoOcspResponder {
        /// The certificate's common name.
        subject: String,
    },
    /// The OCSP response is about other certificates.
    ResponseNotCovering {
        /// The certificate's common name.
        subject: String,
    },
    /// The OCSP responder's certificate is not available.
    ResponderUnavailable {
        /// The certificate's common name.
        subject: String,
    },
    /// The OCSP response is not signed by its responder.
    ResponseNotSigned {
        /// The certificate's common name.
        subject: String,
    },
    /// OCSP reports a certificate of the path as revoked or unknown.
    CertificateNotGood {
        /// The certificate's common name.
        subject: String,
        /// What the responder says.
        status: OcspCertificateStatus,
    },
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Algorithm(error) => write!(formatter, "{error}"),
            Self::Key(error) => write!(formatter, "{error}"),
            Self::Dstu4145(error) => write!(formatter, "DSTU 4145 signing failed: {error}."),
            Self::NothingToSign => write!(formatter, "Nothing to sign."),
            Self::NoTimeStampService => write!(formatter, "Levels T and LT need a time-stamping service."),
            Self::NoOcspService => write!(formatter, "Level LT needs an OCSP service."),
            Self::Service(error) => write!(formatter, "{error}"),
            Self::IncompletePath { top } => write!(
                formatter,
                "The certificate path ends at '{top}' whose issuer is not available; add the CA certificates."
            ),
            Self::NoOcspResponder { subject } => write!(formatter, "No OCSP responder is known for '{subject}'."),
            Self::ResponseNotCovering { subject } => {
                write!(formatter, "The OCSP response does not cover '{subject}'.")
            }
            Self::ResponderUnavailable { subject } => {
                write!(
                    formatter,
                    "The OCSP responder's certificate for '{subject}' is not available."
                )
            }
            Self::ResponseNotSigned { subject } => {
                write!(
                    formatter,
                    "The OCSP response for '{subject}' is not signed by its responder."
                )
            }
            Self::CertificateNotGood { subject, status } => {
                write!(formatter, "The certificate '{subject}' is {status} according to OCSP.")
            }
        }
    }
}

impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Algorithm(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::Dstu4145(error) => Some(error),
            Self::Service(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AlgorithmError> for SigningError {
    fn from(error: AlgorithmError) -> Self {
        Self::Algorithm(error)
    }
}

impl From<KeyError> for SigningError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<ServiceError> for SigningError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}
