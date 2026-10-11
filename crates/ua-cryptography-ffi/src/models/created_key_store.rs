/// A key store made by `create_key_store` and the certificate of its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedKeyStore {
    /// The JKS bytes.
    pub key_store: Vec<u8>,
    /// The self-signed certificate, DER.
    pub certificate: Vec<u8>,
}
