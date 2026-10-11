use crate::BlockSize;
use crate::SetupError;

const BITS_PER_BYTE: usize = 8;

/// The segment length in bytes of CFB and OFB: a multiple of 8 bits from 8 to the block length.
pub(crate) fn segment_bytes_of(segment_bits: usize, block_size: BlockSize) -> Result<usize, SetupError> {
    let is_supported =
        segment_bits >= BITS_PER_BYTE && segment_bits <= block_size.bits() && segment_bits % BITS_PER_BYTE == 0;
    if !is_supported {
        return Err(SetupError::UnsupportedSegmentLength { bits: segment_bits });
    }
    Ok(segment_bits / BITS_PER_BYTE)
}
