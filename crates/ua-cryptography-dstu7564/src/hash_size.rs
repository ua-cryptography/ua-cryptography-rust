use crate::UnsupportedHashSizeError;

const BITS_PER_BYTE: usize = 8;

/// The length of a Kupyna hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashSize {
    /// 256 bits, the 512-bit state.
    Bits256,
    /// 384 bits, the 1024-bit state.
    Bits384,
    /// 512 bits, the 1024-bit state.
    Bits512,
}

impl HashSize {
    /// The size of `bits` bits; refuses anything but 256, 384 and 512.
    pub fn from_bits(bits: usize) -> Result<Self, UnsupportedHashSizeError> {
        match bits {
            256 => Ok(Self::Bits256),
            384 => Ok(Self::Bits384),
            512 => Ok(Self::Bits512),
            _ => Err(UnsupportedHashSizeError { bits }),
        }
    }

    /// The length in bits.
    pub fn bits(self) -> usize {
        match self {
            Self::Bits256 => 256,
            Self::Bits384 => 384,
            Self::Bits512 => 512,
        }
    }

    /// The length in bytes.
    pub fn bytes(self) -> usize {
        self.bits() / BITS_PER_BYTE
    }
}
