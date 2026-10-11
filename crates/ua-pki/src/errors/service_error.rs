use std::fmt;

use crate::errors::{AlgorithmError, CertificateError, OcspError, TimeStampError};

/// Why a request to a PKI service (time-stamping, OCSP, caIssuers download) did not bring a usable answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// The request did not reach the service or the answer did not arrive (connection, timeout, TLS).
    Transport {
        /// The service URL.
        url: String,
        /// What the HTTP client reported.
        message: String,
    },
    /// The service answered with an HTTP status other than 2xx.
    Status {
        /// The service URL.
        url: String,
        /// The HTTP status code.
        status: u16,
        /// The reason phrase.
        reason: String,
    },
    /// The answer is larger than the response cap.
    TooLarge {
        /// The service URL.
        url: String,
        /// The cap in bytes.
        max_bytes: usize,
    },
    /// The request cannot be made: its hash is not supported.
    Request(AlgorithmError),
    /// The time-stamping service's answer is refused.
    TimeStamp(TimeStampError),
    /// The OCSP responder's answer is refused.
    Ocsp(OcspError),
    /// The downloaded certificates are not readable.
    Certificates(CertificateError),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { url, message } => write!(formatter, "{url}: {message}"),
            Self::Status { url, status, reason } => write!(formatter, "{url} answered {status} {reason}."),
            Self::TooLarge { url, max_bytes } => {
                write!(formatter, "{url} answered with more than {max_bytes} bytes.")
            }
            Self::Request(error) => write!(formatter, "{error}"),
            Self::TimeStamp(error) => write!(formatter, "{error}"),
            Self::Ocsp(error) => write!(formatter, "{error}"),
            Self::Certificates(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::TimeStamp(error) => Some(error),
            Self::Ocsp(error) => Some(error),
            Self::Certificates(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AlgorithmError> for ServiceError {
    fn from(error: AlgorithmError) -> Self {
        Self::Request(error)
    }
}

impl From<TimeStampError> for ServiceError {
    fn from(error: TimeStampError) -> Self {
        Self::TimeStamp(error)
    }
}

impl From<OcspError> for ServiceError {
    fn from(error: OcspError) -> Self {
        Self::Ocsp(error)
    }
}

impl From<CertificateError> for ServiceError {
    fn from(error: CertificateError) -> Self {
        Self::Certificates(error)
    }
}
