use std::fmt;

/// Why a mode refuses to encrypt, decrypt, authenticate or (un)wrap one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherFailure {
    /// The mode takes whole blocks only.
    PartialBlock { length: usize, block_bytes: usize },
    /// The IV must be exactly one block.
    WrongIvLength { length: usize, block_bytes: usize },
    /// The IV or nonce is longer than the block.
    IvTooLong { length: usize, block_bytes: usize },
    /// The MAC is defined for a non-empty message, and an empty key is not wrapped.
    EmptyMessage,
    /// The tag length asked for is outside what the mode allows.
    UnsupportedMacLength { bits: usize },
    /// The authenticated ciphertext is shorter than its tag.
    CiphertextShorterThanTag,
    /// The tag does not match: the ciphertext, the associated data, the nonce or the key is not the one tagged.
    TagMismatch,
    /// The wrapped key is shorter than two blocks.
    WrappedDataTooShort,
    /// The integrity block of an unwrapped key is not zero.
    IntegrityCheckFailed,
}

impl fmt::Display for CipherFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialBlock { length, block_bytes } => write!(
                formatter,
                "the length must be a multiple of the block size ({block_bytes} bytes), got {length}"
            ),
            Self::WrongIvLength { length, block_bytes } => {
                write!(
                    formatter,
                    "the IV must be one block ({block_bytes} bytes) long, got {length}"
                )
            }
            Self::IvTooLong { length, block_bytes } => {
                write!(
                    formatter,
                    "the IV is longer than the block ({block_bytes} bytes): {length}"
                )
            }
            Self::EmptyMessage => write!(formatter, "the message is empty"),
            Self::UnsupportedMacLength { bits } => write!(formatter, "unsupported tag length of {bits} bits"),
            Self::CiphertextShorterThanTag => write!(formatter, "the ciphertext is shorter than the tag"),
            Self::TagMismatch => write!(formatter, "tag verification failed"),
            Self::WrappedDataTooShort => write!(formatter, "the wrapped data is too short"),
            Self::IntegrityCheckFailed => write!(formatter, "key unwrap integrity check failed"),
        }
    }
}

impl std::error::Error for CipherFailure {}
