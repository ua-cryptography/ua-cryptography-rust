use std::fmt;

use crate::HexError;

/// Why a value is refused as the standard representation of a field element (DSTU 4145-2002, 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldElementError {
    /// The value has more than m bits.
    TooWide {
        /// The extension degree.
        m: u32,
    },
    /// The hex text is malformed.
    Hex(HexError),
}

impl fmt::Display for FieldElementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooWide { m } => write!(f, "a field element must be a non-negative integer of at most {m} bits"),
            Self::Hex(error) => write!(f, "a field element in hex: {error}"),
        }
    }
}

impl std::error::Error for FieldElementError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Hex(error) => Some(error),
            Self::TooWide { .. } => None,
        }
    }
}

impl From<HexError> for FieldElementError {
    fn from(error: HexError) -> Self {
        Self::Hex(error)
    }
}
