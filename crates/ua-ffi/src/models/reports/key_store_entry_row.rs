use serde::Serialize;

use crate::models::reports::{CertificateDetails, KeyStoreEntryKind};

/// One entry of a key store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyStoreEntryRow {
    /// The alias.
    pub alias: String,
    /// A private key or a trusted certificate.
    pub kind: KeyStoreEntryKind,
    /// When the entry was created, UTC, ISO 8601.
    pub created: String,
    /// The chain of a private key as stored, or the trusted certificate.
    pub certificates: Vec<CertificateDetails>,
}
