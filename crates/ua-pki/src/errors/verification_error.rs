use std::fmt;

use ua_der::DerError;
use ua_xml_c14n::DocumentError;

use crate::errors::{CertificateError, CmsError, ContainerError, OcspError};

/// Why a signed file cannot be verified at all: it is not readable as the format it looks like. A signature that is
/// read but does not hold is not an error: it is a report with failed checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// A CAdES signature is not a readable CMS SignedData.
    Cms(CmsError),
    /// A CAdES attribute is not the DER expected.
    Der(DerError),
    /// A certificate of the certValues attribute is not readable.
    Certificate(CertificateError),
    /// An OCSP response of the revocationValues attribute is not readable.
    Ocsp(OcspError),
    /// An XML document (XAdES, ASiC manifest) is not readable.
    Xml(DocumentError),
    /// An ASiC container is not a readable ZIP archive.
    Container(ContainerError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cms(error) => write!(formatter, "{error}"),
            Self::Der(error) => write!(formatter, "Invalid CMS attribute: {error}."),
            Self::Certificate(error) => write!(formatter, "{error}"),
            Self::Ocsp(error) => write!(formatter, "{error}"),
            Self::Xml(error) => write!(formatter, "{error}"),
            Self::Container(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cms(error) => Some(error),
            Self::Der(error) => Some(error),
            Self::Certificate(error) => Some(error),
            Self::Ocsp(error) => Some(error),
            Self::Xml(error) => Some(error),
            Self::Container(error) => Some(error),
        }
    }
}

impl From<CmsError> for VerificationError {
    fn from(error: CmsError) -> Self {
        Self::Cms(error)
    }
}

impl From<DerError> for VerificationError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<CertificateError> for VerificationError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

impl From<OcspError> for VerificationError {
    fn from(error: OcspError) -> Self {
        Self::Ocsp(error)
    }
}

impl From<DocumentError> for VerificationError {
    fn from(error: DocumentError) -> Self {
        Self::Xml(error)
    }
}

impl From<ContainerError> for VerificationError {
    fn from(error: ContainerError) -> Self {
        Self::Container(error)
    }
}
