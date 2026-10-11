use std::fmt;

/// Why data is neither DER nor PEM (RFC 7468) text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PemError {
    /// The BEGIN line has no matching END line.
    Unterminated {
        /// The label of the block, e.g. `CERTIFICATE`.
        label: String,
    },
    /// The text between the markers (or the whole text) is not base64.
    NotBase64 {
        /// The label that was expected.
        label: String,
    },
}

impl fmt::Display for PemError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PemError::Unterminated { label } => write!(formatter, "PEM block {label} is not terminated"),
            PemError::NotBase64 { label } => write!(formatter, "the data is neither DER nor PEM ({label})"),
        }
    }
}

impl std::error::Error for PemError {}
