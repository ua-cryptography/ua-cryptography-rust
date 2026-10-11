use std::fmt;

use ua_cryptography_gost::SubstitutionTableError;

/// Why the generator of Appendix А refuses to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RandomGeneratorError {
    /// The GOST 28147 substitution table is malformed.
    SubstitutionTable(SubstitutionTableError),
}

impl fmt::Display for RandomGeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SubstitutionTable(error) => write!(f, "the generator's substitution table: {error}"),
        }
    }
}

impl std::error::Error for RandomGeneratorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SubstitutionTable(error) => Some(error),
        }
    }
}

impl From<SubstitutionTableError> for RandomGeneratorError {
    fn from(error: SubstitutionTableError) -> Self {
        Self::SubstitutionTable(error)
    }
}
