use std::fmt;

/// Why (r, s) cannot become a signature D = S‖R, or D cannot be split (DSTU 4145-2002, 5.10, 5.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureEncodingError {
    /// L_D is not a positive multiple of 16.
    LengthNotMultipleOf16(u32),
    /// r or s is zero or does not fit into L_D / 2 bits.
    ValueOutOfRange,
    /// The signature has no bytes.
    Empty,
}

impl fmt::Display for SignatureEncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthNotMultipleOf16(bits) => {
                write!(f, "the signature length L_D = {bits} must be a positive multiple of 16")
            }
            Self::ValueOutOfRange => write!(f, "r and s must be positive and fit into L_D / 2 bits"),
            Self::Empty => write!(f, "empty signature"),
        }
    }
}

impl std::error::Error for SignatureEncodingError {}
