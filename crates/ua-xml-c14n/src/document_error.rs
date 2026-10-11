use std::fmt;

/// Why bytes are not an XML document the canonicalizer accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentError {
    /// The bytes (no byte order mark, or the UTF-8 one) are not UTF-8.
    InvalidUtf8,
    /// The bytes after a UTF-16 byte order mark are not UTF-16.
    InvalidUtf16,
    /// The XML declaration names an encoding other than UTF-8 or UTF-16, and the text is not plain ASCII.
    UnsupportedEncoding {
        /// The encoding the declaration names.
        name: String,
    },
    /// The document has a document type declaration; DTDs are refused (no entity expansion, no XXE).
    DtdRefused,
    /// Elements are nested more than 64 levels deep.
    TooDeep,
    /// The text is not well-formed namespace-aware XML.
    Malformed {
        /// What the parser reported.
        message: String,
    },
}

impl fmt::Display for DocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DocumentError::InvalidUtf8 => write!(formatter, "the XML document is not valid UTF-8"),
            DocumentError::InvalidUtf16 => write!(formatter, "the XML document is not valid UTF-16"),
            DocumentError::UnsupportedEncoding { name } => {
                write!(formatter, "the XML encoding '{name}' is not supported")
            }
            DocumentError::DtdRefused => write!(formatter, "XML document type declarations are refused"),
            DocumentError::TooDeep => write!(formatter, "XML elements are nested too deep"),
            DocumentError::Malformed { message } => write!(formatter, "malformed XML: {message}"),
        }
    }
}

impl std::error::Error for DocumentError {}
