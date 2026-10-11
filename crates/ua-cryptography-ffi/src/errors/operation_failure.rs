use std::fmt;

use ua_cryptography_dstu4145::{
    NamedCurveError, PublicKeyCheckFailure, RandomGeneratorError, SignatureEncodingError, SigningError,
};
use ua_cryptography_dstu7564::UnsupportedHashSizeError;
use ua_cryptography_dstu7624::{CipherFailure, SetupError};
use ua_cryptography_gf2m::PointError;
use ua_cryptography_gost::SubstitutionTableError;
use ua_cryptography_pki::{
    AlgorithmError, CertificateError, ContainerError, DistinguishedNameError, KeyError, KeyStoreError,
    VerificationError,
};

use crate::errors::FailureKind;

/// Why one call of the library did not finish: its kind and the refusing crate's own text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationFailure {
    /// The kind, which decides the status code.
    pub kind: FailureKind,
    /// The refusal in the words of the crate that refused, cause included.
    pub message: String,
}

impl OperationFailure {
    /// A refusal of `kind` with `message`.
    pub fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// An argument the library refuses.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(FailureKind::InvalidArgument, message)
    }
}

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for OperationFailure {}

impl From<SubstitutionTableError> for OperationFailure {
    fn from(error: SubstitutionTableError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<UnsupportedHashSizeError> for OperationFailure {
    fn from(error: UnsupportedHashSizeError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<SetupError> for OperationFailure {
    fn from(error: SetupError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<CipherFailure> for OperationFailure {
    fn from(error: CipherFailure) -> Self {
        let kind = match error {
            CipherFailure::TagMismatch | CipherFailure::IntegrityCheckFailed => FailureKind::AuthenticationFailed,
            _ => FailureKind::InvalidArgument,
        };
        Self::new(kind, error.to_string())
    }
}

impl From<NamedCurveError> for OperationFailure {
    fn from(error: NamedCurveError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<SigningError> for OperationFailure {
    fn from(error: SigningError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<SignatureEncodingError> for OperationFailure {
    fn from(error: SignatureEncodingError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<PublicKeyCheckFailure> for OperationFailure {
    fn from(error: PublicKeyCheckFailure) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<RandomGeneratorError> for OperationFailure {
    fn from(error: RandomGeneratorError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<PointError> for OperationFailure {
    fn from(error: PointError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<KeyStoreError> for OperationFailure {
    fn from(error: KeyStoreError) -> Self {
        let kind = match error {
            KeyStoreError::IntegrityCheckFailed | KeyStoreError::WrongKeyPassword => FailureKind::WrongPassword,
            KeyStoreError::NoPrivateKey { .. }
            | KeyStoreError::NoSigningKey
            | KeyStoreError::SeveralKeys { .. }
            | KeyStoreError::DuplicateAlias { .. }
            | KeyStoreError::AliasTooLong => FailureKind::InvalidArgument,
            _ => FailureKind::UnreadableInput,
        };
        Self::new(kind, error.to_string())
    }
}

impl From<CertificateError> for OperationFailure {
    fn from(error: CertificateError) -> Self {
        Self::new(FailureKind::UnreadableInput, error.to_string())
    }
}

impl From<KeyError> for OperationFailure {
    fn from(error: KeyError) -> Self {
        Self::new(FailureKind::UnreadableInput, error.to_string())
    }
}

impl From<DistinguishedNameError> for OperationFailure {
    fn from(error: DistinguishedNameError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<AlgorithmError> for OperationFailure {
    fn from(error: AlgorithmError) -> Self {
        Self::invalid_argument(error.to_string())
    }
}

impl From<ContainerError> for OperationFailure {
    fn from(error: ContainerError) -> Self {
        let kind = match error {
            ContainerError::InvalidEntryName { .. } => FailureKind::InvalidArgument,
            _ => FailureKind::UnreadableInput,
        };
        Self::new(kind, error.to_string())
    }
}

impl From<VerificationError> for OperationFailure {
    fn from(error: VerificationError) -> Self {
        Self::new(FailureKind::UnreadableInput, error.to_string())
    }
}

impl From<ua_cryptography_pki::SigningError> for OperationFailure {
    fn from(error: ua_cryptography_pki::SigningError) -> Self {
        let kind = match error {
            ua_cryptography_pki::SigningError::Service(_)
            | ua_cryptography_pki::SigningError::NoOcspResponder { .. }
            | ua_cryptography_pki::SigningError::ResponseNotCovering { .. }
            | ua_cryptography_pki::SigningError::ResponderUnavailable { .. }
            | ua_cryptography_pki::SigningError::ResponseNotSigned { .. }
            | ua_cryptography_pki::SigningError::CertificateNotGood { .. } => FailureKind::ServiceFailure,
            _ => FailureKind::InvalidArgument,
        };
        Self::new(kind, error.to_string())
    }
}
