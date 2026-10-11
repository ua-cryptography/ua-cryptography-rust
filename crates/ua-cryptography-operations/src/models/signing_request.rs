use std::fmt;

use ua_cryptography_pki::SignedFile;

use crate::models::SigningOptions;

/// What to sign, with which key.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningRequest {
    /// The JKS key store.
    pub key_store: Vec<u8>,
    /// The password of the store and of its key.
    pub password: String,
    /// The key entry; absent: the one signing key of the store.
    pub alias: Option<String>,
    /// The files, each under its name; CAdES and ASiC-S take exactly one.
    pub files: Vec<SignedFile>,
    /// CA certificates completing the signer's chain (DER, PEM or a bundle each).
    pub certificates: Vec<Vec<u8>>,
    /// The format, level and services.
    pub options: SigningOptions,
}

impl fmt::Debug for SigningRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningRequest")
            .field("key_store", &self.key_store.len())
            .field("password", &"<redacted>")
            .field("alias", &self.alias)
            .field("files", &self.files.iter().map(|file| &file.name).collect::<Vec<_>>())
            .field("certificates", &self.certificates.len())
            .field("options", &self.options)
            .finish()
    }
}
