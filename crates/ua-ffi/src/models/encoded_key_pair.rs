use std::fmt;

/// A DSTU 4145 key pair as bytes: d big-endian, ⌈L(n) / 8⌉ bytes; Q compressed (6.9), big-endian, ⌈m / 8⌉ bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedKeyPair {
    /// The private key d.
    pub private_key: Vec<u8>,
    /// The compressed public key Q = −dP.
    pub public_key: Vec<u8>,
}

impl fmt::Debug for EncodedKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedKeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}
