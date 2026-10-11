use std::fmt;

use ua_der::DerError;

use crate::errors::{CertificateError, KeyError, SigningKeyError};

/// Why a JKS key store, one of its entries or the key chosen from it is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    /// The file is shorter than the smallest key store.
    TooShort,
    /// The magic number is not FEEDFEED (JCEKS and PKCS#12 are other formats).
    NotJks,
    /// The SHA-1 integrity check fails: a wrong password or a damaged file.
    IntegrityCheckFailed,
    /// The version is neither 1 nor 2.
    UnsupportedVersion {
        /// The version found.
        version: u32,
    },
    /// The data ends inside an entry.
    Truncated,
    /// An entry tag is neither 1 (private key) nor 2 (trusted certificate).
    UnknownEntryType {
        /// The tag found.
        tag: u32,
    },
    /// Bytes follow the last entry.
    TrailingData,
    /// An alias is not Java's modified UTF-8.
    InvalidModifiedUtf8,
    /// An entry's creation time is out of range.
    InvalidCreationTime,
    /// A certificate type other than X.509.
    UnsupportedCertificateType {
        /// The type named.
        name: String,
    },
    /// A stored certificate is not readable.
    Certificate(CertificateError),
    /// The protected key is not an EncryptedPrivateKeyInfo.
    Der(DerError),
    /// The key is protected by another algorithm than the Sun JKS key protector.
    UnsupportedKeyProtection {
        /// The protection algorithm OID.
        oid: String,
    },
    /// The protected key is shorter than its salt and check value.
    ProtectedKeyTooShort,
    /// The key protector's check fails: a wrong key password.
    WrongKeyPassword,
    /// The decrypted key is not a DSTU 4145 PKCS#8 key.
    Key(KeyError),
    /// The chain holds DSTU 4145 certificates, none of them the key's.
    KeyCertificateMismatch {
        /// The alias of the entry.
        alias: String,
    },
    /// The alias is already taken.
    DuplicateAlias {
        /// The alias.
        alias: String,
    },
    /// The alias is longer than 65535 bytes of modified UTF-8.
    AliasTooLong,
    /// The store has no private key under the alias.
    NoPrivateKey {
        /// The alias asked for.
        alias: String,
    },
    /// The store holds no signing key.
    NoSigningKey,
    /// The store holds several signing keys and no alias was given.
    SeveralKeys {
        /// The aliases of every private key.
        aliases: Vec<String>,
    },
    /// The key and its chain do not make a signing key.
    SigningKey(SigningKeyError),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(formatter, "The file is too short to be a JKS key store."),
            Self::NotJks => write!(formatter, "Not a JKS key store (JCEKS and PKCS#12 are not supported)."),
            Self::IntegrityCheckFailed => {
                write!(
                    formatter,
                    "JKS integrity check failed: wrong password or a damaged file."
                )
            }
            Self::UnsupportedVersion { version } => write!(formatter, "Unsupported JKS version {version}."),
            Self::Truncated => write!(formatter, "Truncated JKS key store."),
            Self::UnknownEntryType { tag } => write!(formatter, "Unknown JKS entry type {tag}."),
            Self::TrailingData => write!(formatter, "Unexpected data after the last JKS entry."),
            Self::InvalidModifiedUtf8 => write!(formatter, "Invalid modified UTF-8 in a JKS alias."),
            Self::InvalidCreationTime => write!(formatter, "Invalid creation time of a JKS entry."),
            Self::UnsupportedCertificateType { name } => {
                write!(formatter, "Certificate type {name} is not supported.")
            }
            Self::Certificate(error) => write!(formatter, "{error}"),
            Self::Der(error) => write!(formatter, "Invalid protected key: {error}."),
            Self::UnsupportedKeyProtection { oid } => write!(
                formatter,
                "Key protection {oid} is not supported (only the Sun JKS key protector)."
            ),
            Self::ProtectedKeyTooShort => write!(formatter, "The protected key is too short."),
            Self::WrongKeyPassword => write!(formatter, "The key protector check failed: wrong key password."),
            Self::Key(error) => write!(formatter, "{error}"),
            Self::KeyCertificateMismatch { alias } => {
                write!(
                    formatter,
                    "The private key of '{alias}' does not match its certificate."
                )
            }
            Self::DuplicateAlias { alias } => write!(formatter, "The key store already has an entry '{alias}'."),
            Self::AliasTooLong => write!(formatter, "The string is too long for a JKS entry."),
            Self::NoPrivateKey { alias } => write!(formatter, "The key store has no private key '{alias}'."),
            Self::NoSigningKey => write!(formatter, "The key store holds no signing key."),
            Self::SeveralKeys { aliases } => write!(
                formatter,
                "The key store holds several keys; choose one by alias: {}.",
                aliases.join(", ")
            ),
            Self::SigningKey(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificate(error) => Some(error),
            Self::Der(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::SigningKey(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CertificateError> for KeyStoreError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

impl From<DerError> for KeyStoreError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<KeyError> for KeyStoreError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<SigningKeyError> for KeyStoreError {
    fn from(error: SigningKeyError) -> Self {
        Self::SigningKey(error)
    }
}
