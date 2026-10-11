use std::fmt;

/// Why dotted-decimal text is not an object identifier (X.690, 8.19).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidError {
    /// Fewer than two arcs.
    TooFewArcs,
    /// An arc is empty or holds something other than decimal digits.
    NotANumber,
    /// The first arc is above 2, or the second is 40 or more under a first arc of 0 or 1.
    RootArcsOutOfRange,
}

impl fmt::Display for OidError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            OidError::TooFewArcs => "it has fewer than two arcs",
            OidError::NotANumber => "an arc is not a decimal number",
            OidError::RootArcsOutOfRange => "the first two arcs are out of range",
        };
        write!(formatter, "invalid object identifier: {reason}")
    }
}

impl std::error::Error for OidError {}
