use std::fmt;

/// Why the cipher or a mode refuses its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupError {
    /// The block length is not 128, 256 or 512 bits.
    UnsupportedBlockSize { bits: usize },
    /// The key is neither one nor two blocks long, or longer than 512 bits (DSTU 7624:2014, table 6.1).
    WrongKeyLength { key_bytes: usize, block_bytes: usize },
    /// A CFB or OFB segment is not a multiple of 8 bits between 8 and the block length.
    UnsupportedSegmentLength { bits: usize },
    /// A MAC length outside what the mode allows.
    UnsupportedMacLength { bits: usize },
    /// The CCM length field Nb is not 4, 6 or 8 bytes.
    UnsupportedNb { nb: usize },
}

impl fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedBlockSize { bits } => {
                write!(formatter, "block length must be 128, 256 or 512 bits, got {bits}")
            }
            Self::WrongKeyLength { key_bytes, block_bytes } => write!(
                formatter,
                "a {}-bit block needs a {}- or {}-bit key (at most 512), got {} bits",
                block_bytes * 8,
                block_bytes * 8,
                block_bytes * 16,
                key_bytes * 8
            ),
            Self::UnsupportedSegmentLength { bits } => {
                write!(
                    formatter,
                    "the segment must be a multiple of 8 bits from 8 to the block length, got {bits}"
                )
            }
            Self::UnsupportedMacLength { bits } => write!(formatter, "unsupported MAC length of {bits} bits"),
            Self::UnsupportedNb { nb } => write!(formatter, "Nb must be 4, 6 or 8, got {nb}"),
        }
    }
}

impl std::error::Error for SetupError {}
