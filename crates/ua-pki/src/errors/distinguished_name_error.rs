use std::fmt;

/// Why the text of a distinguished name ("CN=Name, O=Organization, C=UA") is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistinguishedNameError {
    /// A component has no `=` or no key before it.
    InvalidComponent {
        /// The component as written.
        component: String,
    },
    /// The key is neither a known RFC 4514 key nor an OID.
    UnknownAttributeType {
        /// The key as written.
        key: String,
    },
    /// The text holds no component.
    Empty,
}

impl fmt::Display for DistinguishedNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidComponent { component } => {
                write!(formatter, "Invalid distinguished name component '{component}'.")
            }
            Self::UnknownAttributeType { key } => write!(formatter, "Unknown attribute type '{key}'."),
            Self::Empty => write!(formatter, "The distinguished name is empty."),
        }
    }
}

impl std::error::Error for DistinguishedNameError {}
