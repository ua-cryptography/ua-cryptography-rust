use crate::SetupError;

const BITS_PER_BYTE: usize = 8;
const BITS_PER_WORD: usize = 64;

/// The block length of Kalyna.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockSize {
    /// 128 bits, keys of 128 or 256 bits.
    Bits128,
    /// 256 bits, keys of 256 or 512 bits.
    Bits256,
    /// 512 bits, a key of 512 bits.
    Bits512,
}

impl BlockSize {
    /// The block length of `bits` bits; refuses anything but 128, 256 and 512.
    pub fn from_bits(bits: usize) -> Result<Self, SetupError> {
        match bits {
            128 => Ok(Self::Bits128),
            256 => Ok(Self::Bits256),
            512 => Ok(Self::Bits512),
            _ => Err(SetupError::UnsupportedBlockSize { bits }),
        }
    }

    /// The length in bits.
    pub fn bits(self) -> usize {
        match self {
            Self::Bits128 => 128,
            Self::Bits256 => 256,
            Self::Bits512 => 512,
        }
    }

    /// The length in bytes.
    pub fn bytes(self) -> usize {
        self.bits() / BITS_PER_BYTE
    }

    /// The number of 64-bit columns of the state.
    pub(crate) fn words(self) -> usize {
        self.bits() / BITS_PER_WORD
    }
}
