use std::fmt;

use crate::models::simple_types::SignatureHash;

/// A new JKS key store with one DSTU 4145 key and its self-signed certificate, as `ua-sign keygen` makes it.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyStoreRequest {
    /// The subject, e.g. "CN=Name,O=Organization,C=UA".
    pub subject: String,
    /// The alias of the key entry.
    pub alias: String,
    /// The degree of the curve of table Г.1.
    pub m: u32,
    /// How many days the certificate is valid from now.
    pub validity_days: u32,
    /// The hash the certificate is signed over.
    pub signature_hash: SignatureHash,
    /// The password of the store and of its key.
    pub password: String,
}

impl fmt::Debug for KeyStoreRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyStoreRequest")
            .field("subject", &self.subject)
            .field("alias", &self.alias)
            .field("m", &self.m)
            .field("validity_days", &self.validity_days)
            .field("signature_hash", &self.signature_hash)
            .field("password", &"<redacted>")
            .finish()
    }
}
