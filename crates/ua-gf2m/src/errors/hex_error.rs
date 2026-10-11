use std::fmt;

/// Why a hex string is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// No hex digit at all.
    Empty,
    /// A character that is neither a hex digit nor an ignored separator.
    InvalidCharacter(char),
    /// A byte string with an odd number of hex digits.
    OddLength,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty hex string"),
            Self::InvalidCharacter(character) => write!(f, "invalid hex character '{character}'"),
            Self::OddLength => write!(f, "a hex byte string must have an even number of digits"),
        }
    }
}

impl std::error::Error for HexError {}
