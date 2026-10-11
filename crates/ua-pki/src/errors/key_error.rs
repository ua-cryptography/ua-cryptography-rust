use std::fmt;

use ua_der::DerError;
use ua_dstu4145::{DomainParametersError, ParameterCheckFailure, PublicKeyCheckFailure};
use ua_gf2m::{CurveError, FieldError, PointError};
use ua_gost::SubstitutionTableError;

/// Why a DSTU 4145 key (SubjectPublicKeyInfo, PKCS#8 PrivateKeyInfo or their AlgorithmIdentifier) is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The structure is not the DER expected.
    Der(DerError),
    /// The key algorithm is not DSTU 4145.
    NotDstu4145 {
        /// The key algorithm OID.
        oid: String,
    },
    /// The certificate's key is of another algorithm.
    NotDstu4145Certificate {
        /// The certificate's subject.
        subject: String,
        /// The key algorithm OID.
        oid: String,
    },
    /// The named-curve OID is not one of table Г.1.
    UnknownNamedCurve {
        /// The curve OID.
        oid: String,
    },
    /// The explicit field degree is outside tables 1 and 2 (163–509).
    UnsupportedFieldDegree {
        /// The degree m found.
        m: i64,
    },
    /// The explicit field is refused.
    InvalidField(FieldError),
    /// The explicit curve is refused.
    InvalidCurve(CurveError),
    /// A compressed point does not decode.
    InvalidPoint(PointError),
    /// The explicit parameters do not form domain parameters (section 7).
    InvalidDomain(DomainParametersError),
    /// The explicit parameters fail a check of section 8.
    InvalidDomainParameters(ParameterCheckFailure),
    /// The public key fails a check of 10.1.
    InvalidPublicKey(PublicKeyCheckFailure),
    /// The DKE is not a GOST 34.311 S-box table.
    InvalidDke(SubstitutionTableError),
    /// The private key d is not in (0, n).
    PrivateKeyOutOfRange,
    /// The point has no compressed form (6.9), so it cannot be written in SubjectPublicKeyInfo.
    NoCompressedForm,
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Der(error) => write!(formatter, "Invalid DSTU 4145 key structure: {error}."),
            Self::NotDstu4145 { oid } => write!(formatter, "Key algorithm {oid} is not DSTU 4145."),
            Self::NotDstu4145Certificate { subject, oid } => {
                write!(formatter, "The key of '{subject}' is not a DSTU 4145 key ({oid}).")
            }
            Self::UnknownNamedCurve { oid } => write!(formatter, "Unknown DSTU 4145 named curve {oid}."),
            Self::UnsupportedFieldDegree { m } => write!(
                formatter,
                "Unsupported DSTU 4145 field degree m = {m} (tables 1 and 2 cover 163 – 509)."
            ),
            Self::InvalidField(error) => write!(formatter, "Invalid DSTU 4145 field: {error}."),
            Self::InvalidCurve(error) => write!(formatter, "Invalid DSTU 4145 curve: {error}."),
            Self::InvalidPoint(error) => write!(formatter, "Invalid DSTU 4145 point: {error}."),
            Self::InvalidDomain(error) => write!(formatter, "Invalid DSTU 4145 domain parameters: {error}."),
            Self::InvalidDomainParameters(failure) => {
                write!(formatter, "Invalid DSTU 4145 domain parameters: {failure}")
            }
            Self::InvalidPublicKey(failure) => write!(formatter, "Invalid DSTU 4145 public key: {failure}"),
            Self::InvalidDke(error) => write!(formatter, "Invalid GOST 34.311 DKE: {error}."),
            Self::PrivateKeyOutOfRange => write!(formatter, "The DSTU 4145 private key is out of range (0, n)."),
            Self::NoCompressedForm => write!(formatter, "The DSTU 4145 public key has no compressed form."),
        }
    }
}

impl std::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Der(error) => Some(error),
            Self::InvalidField(error) => Some(error),
            Self::InvalidCurve(error) => Some(error),
            Self::InvalidPoint(error) => Some(error),
            Self::InvalidDomain(error) => Some(error),
            Self::InvalidDomainParameters(failure) => Some(failure),
            Self::InvalidPublicKey(failure) => Some(failure),
            Self::InvalidDke(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DerError> for KeyError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}
