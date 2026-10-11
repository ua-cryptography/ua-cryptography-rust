use std::fmt;

/// Why a GOST 28147 substitution table, or the DKE it is expanded from, is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubstitutionTableError {
    /// The expanded table does not have 128 entries.
    WrongTableLength { length: usize },
    /// An entry of the expanded table is not a 4-bit value.
    EntryOutOfRange { index: usize, value: u8 },
    /// The DKE is not 64 bytes long.
    WrongDkeLength { length: usize },
}

impl fmt::Display for SubstitutionTableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongTableLength { length } => {
                write!(
                    formatter,
                    "a GOST 28147 substitution table has 128 entries, got {length}"
                )
            }
            Self::EntryOutOfRange { index, value } => {
                write!(formatter, "S-box entry {index} is {value}, not a 4-bit value")
            }
            Self::WrongDkeLength { length } => {
                write!(formatter, "a DKE must be 64 bytes long, got {length}")
            }
        }
    }
}

impl std::error::Error for SubstitutionTableError {}
