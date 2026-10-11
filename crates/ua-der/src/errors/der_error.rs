use std::fmt;

/// Why bytes are not the ASN.1 element (X.690) a reader asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerError {
    /// The data ends inside an identifier or a length.
    Truncated,
    /// The identifier uses the high-tag-number form (tag number 31 and above).
    HighTagNumber,
    /// A primitive element has the indefinite length form.
    IndefinitePrimitive,
    /// An indefinite-length element has no end-of-contents octets.
    MissingEndOfContents,
    /// The length uses more than four octets, or the octets are missing.
    InvalidLength,
    /// The length is above 2^31 - 1.
    LengthTooLarge,
    /// The length runs past the end of the data.
    LengthExceedsData,
    /// Bytes follow the one element that was expected.
    TrailingBytes {
        /// How many bytes follow.
        count: usize,
    },
    /// Elements are nested more than 64 levels deep.
    TooDeep,
    /// Children were asked of a primitive element.
    Primitive {
        /// The identifier octet of the element.
        tag: u8,
    },
    /// A child index is past the last child.
    MissingChild {
        /// The identifier octet of the parent.
        tag: u8,
        /// How many children the parent has.
        count: usize,
        /// The index asked for.
        index: usize,
    },
    /// The identifier octet is not the one expected.
    UnexpectedTag {
        /// The identifier octet expected.
        expected: u8,
        /// The identifier octet found.
        found: u8,
    },
    /// An INTEGER has no contents octets.
    EmptyInteger,
    /// An INTEGER does not fit the type asked for.
    IntegerOutOfRange,
    /// A non-negative INTEGER was asked for and the value is negative.
    NegativeInteger,
    /// A BOOLEAN does not have exactly one contents octet.
    InvalidBoolean,
    /// An OBJECT IDENTIFIER is empty or its last subidentifier is unfinished.
    InvalidObjectIdentifier,
    /// A BIT STRING is empty or claims more than 7 unused bits.
    InvalidBitString,
    /// The element is not one of the character string types.
    NotCharacterString {
        /// The identifier octet found.
        tag: u8,
    },
    /// The element is neither UTCTime nor GeneralizedTime.
    NotTime {
        /// The identifier octet found.
        tag: u8,
    },
    /// The text of a UTCTime or GeneralizedTime is not a valid time.
    InvalidTime {
        /// The contents as text.
        text: String,
    },
}

impl fmt::Display for DerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerError::Truncated => write!(formatter, "truncated ASN.1 element"),
            DerError::HighTagNumber => write!(formatter, "high-tag-number ASN.1 forms are not supported"),
            DerError::IndefinitePrimitive => {
                write!(formatter, "a primitive ASN.1 element cannot have an indefinite length")
            }
            DerError::MissingEndOfContents => write!(formatter, "missing end-of-contents octets"),
            DerError::InvalidLength => write!(formatter, "invalid ASN.1 length"),
            DerError::LengthTooLarge => write!(formatter, "ASN.1 length is too large"),
            DerError::LengthExceedsData => write!(formatter, "ASN.1 length exceeds the data"),
            DerError::TrailingBytes { count } => write!(formatter, "unexpected {count} bytes after the ASN.1 element"),
            DerError::TooDeep => write!(formatter, "ASN.1 nesting is too deep"),
            DerError::Primitive { tag } => {
                write!(
                    formatter,
                    "ASN.1 element with tag 0x{tag:02X} is primitive and has no children"
                )
            }
            DerError::MissingChild { tag, count, index } => write!(
                formatter,
                "ASN.1 element with tag 0x{tag:02X} has {count} children, element {index} is missing"
            ),
            DerError::UnexpectedTag { expected, found } => {
                write!(formatter, "expected ASN.1 tag 0x{expected:02X}, found 0x{found:02X}")
            }
            DerError::EmptyInteger => write!(formatter, "empty INTEGER"),
            DerError::IntegerOutOfRange => write!(formatter, "INTEGER does not fit into the requested type"),
            DerError::NegativeInteger => write!(formatter, "INTEGER is negative"),
            DerError::InvalidBoolean => write!(formatter, "invalid BOOLEAN"),
            DerError::InvalidObjectIdentifier => write!(formatter, "invalid OBJECT IDENTIFIER"),
            DerError::InvalidBitString => write!(formatter, "invalid BIT STRING"),
            DerError::NotCharacterString { tag } => {
                write!(formatter, "ASN.1 tag 0x{tag:02X} is not a character string")
            }
            DerError::NotTime { tag } => write!(formatter, "ASN.1 tag 0x{tag:02X} is not a time"),
            DerError::InvalidTime { text } => write!(formatter, "invalid ASN.1 time '{text}'"),
        }
    }
}

impl std::error::Error for DerError {}
