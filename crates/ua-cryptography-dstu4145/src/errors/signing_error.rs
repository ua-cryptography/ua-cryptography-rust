use std::fmt;

/// Why a key or a signature is not produced (DSTU 4145-2002, sections 9, 12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    /// The private key d is not in 0 < d < n.
    PrivateKeyOutOfRange,
    /// L_D is not a multiple of 16 or is below 2 L(n) (12.3).
    InvalidSignatureLength(u32),
    /// The hash code has no bytes.
    EmptyHash,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrivateKeyOutOfRange => write!(f, "the private key must satisfy 0 < d < n"),
            Self::InvalidSignatureLength(bits) => {
                write!(f, "L_D = {bits} must be a multiple of 16 and at least 2 L(n) (12.3)")
            }
            Self::EmptyHash => write!(f, "empty hash"),
        }
    }
}

impl std::error::Error for SigningError {}
