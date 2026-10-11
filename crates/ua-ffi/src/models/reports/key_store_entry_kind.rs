use serde::Serialize;

/// The kind of a JKS entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStoreEntryKind {
    /// A protected private key with its chain.
    PrivateKey,
    /// A trusted certificate.
    TrustedCertificate,
}
