use time::OffsetDateTime;

use crate::keystore::{JksPrivateKeyEntry, JksTrustedCertificateEntry};

/// An entry of a key store.
// A store holds a handful of entries: boxing the certificate would only complicate matching on them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JksEntry {
    /// A protected private key with its chain.
    PrivateKey(JksPrivateKeyEntry),
    /// A trusted certificate.
    TrustedCertificate(JksTrustedCertificateEntry),
}

impl JksEntry {
    /// The alias.
    pub fn alias(&self) -> &str {
        match self {
            Self::PrivateKey(entry) => &entry.alias,
            Self::TrustedCertificate(entry) => &entry.alias,
        }
    }

    /// When the entry was created.
    pub fn created(&self) -> OffsetDateTime {
        match self {
            Self::PrivateKey(entry) => entry.created,
            Self::TrustedCertificate(entry) => entry.created,
        }
    }
}
