use std::fmt;

/// A Kupyna hash length other than 256, 384 or 512 bits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedHashSizeError {
    /// The length asked for, in bits.
    pub bits: usize,
}

impl fmt::Display for UnsupportedHashSizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "supported hash sizes are 256, 384 and 512 bits, got {}",
            self.bits
        )
    }
}

impl std::error::Error for UnsupportedHashSizeError {}
