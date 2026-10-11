use std::fmt;

use ua_cryptography_gost::SubstitutionTableError;

/// Why an algorithm identifier (an OID, an XML-DSig URI or a hash name) is not one of the national PKI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmError {
    /// The hash OID is not supported.
    UnsupportedHash {
        /// The OID given.
        oid: String,
    },
    /// The signature algorithm is neither DSTU 4145 with GOST 34.311 nor with DSTU 7564.
    UnsupportedSignatureAlgorithm {
        /// The OID given.
        oid: String,
    },
    /// No DSTU 4145 signature algorithm goes with the hash.
    NoSignatureAlgorithm {
        /// The hash OID.
        hash_oid: String,
    },
    /// No XML-DSig DigestMethod goes with the hash.
    NoXmlDigestMethod {
        /// The hash OID.
        hash_oid: String,
    },
    /// No XML-DSig SignatureMethod goes with the hash.
    NoXmlSignatureMethod {
        /// The hash OID.
        hash_oid: String,
    },
    /// The XML-DSig DigestMethod or SignatureMethod URI is not supported.
    UnsupportedXmlAlgorithm {
        /// The URI given.
        uri: String,
    },
    /// The hash name is neither dstu7564 nor gost34311 nor a supported OID.
    UnknownHashName {
        /// The name given.
        name: String,
    },
    /// The GOST 34.311 S-box table (DKE) is refused.
    InvalidDke(SubstitutionTableError),
}

impl fmt::Display for AlgorithmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHash { oid } => write!(formatter, "Hash algorithm {oid} is not supported."),
            Self::UnsupportedSignatureAlgorithm { oid } => {
                write!(formatter, "Signature algorithm {oid} is not supported.")
            }
            Self::NoSignatureAlgorithm { hash_oid } => {
                write!(
                    formatter,
                    "No DSTU 4145 signature algorithm is defined for hash {hash_oid}."
                )
            }
            Self::NoXmlDigestMethod { hash_oid } => write!(formatter, "No XML digest method for hash {hash_oid}."),
            Self::NoXmlSignatureMethod { hash_oid } => {
                write!(formatter, "No XML signature method for hash {hash_oid}.")
            }
            Self::UnsupportedXmlAlgorithm { uri } => write!(formatter, "XML algorithm {uri} is not supported."),
            Self::UnknownHashName { name } => {
                write!(formatter, "Unknown hash '{name}' (expected dstu7564 or gost34311).")
            }
            Self::InvalidDke(error) => write!(formatter, "Invalid GOST 34.311 DKE: {error}."),
        }
    }
}

impl std::error::Error for AlgorithmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidDke(error) => Some(error),
            _ => None,
        }
    }
}
