use crate::CipherFailure;

const WORD_BYTES: usize = 8;

/// `target ⊕= source` over the length of `target`.
pub(crate) fn xor_into(target: &mut [u8], source: &[u8]) {
    for (target_byte, &source_byte) in target.iter_mut().zip(source) {
        *target_byte ^= source_byte;
    }
}

/// A value of at most one block placed at the end of a zero block.
pub(crate) fn right_aligned(value: &[u8], block_bytes: usize) -> Result<Vec<u8>, CipherFailure> {
    if value.len() > block_bytes {
        return Err(CipherFailure::IvTooLong {
            length: value.len(),
            block_bytes,
        });
    }
    let mut block = vec![0u8; block_bytes];
    block[block_bytes - value.len()..].copy_from_slice(value);
    Ok(block)
}

/// Refuses a length that is not a whole number of blocks.
pub(crate) fn check_whole_blocks(length: usize, block_bytes: usize) -> Result<(), CipherFailure> {
    if length % block_bytes != 0 {
        return Err(CipherFailure::PartialBlock { length, block_bytes });
    }
    Ok(())
}

/// Refuses an IV that is not exactly one block.
pub(crate) fn check_one_block_iv(iv: &[u8], block_bytes: usize) -> Result<(), CipherFailure> {
    if iv.len() != block_bytes {
        return Err(CipherFailure::WrongIvLength {
            length: iv.len(),
            block_bytes,
        });
    }
    Ok(())
}

/// Equality whose running time does not depend on where the inputs differ.
pub(crate) fn is_equal_in_constant_time(first: &[u8], second: &[u8]) -> bool {
    if first.len() != second.len() {
        return false;
    }
    let difference = first
        .iter()
        .zip(second)
        .fold(0u8, |accumulated, (&a, &b)| accumulated | (a ^ b));
    difference == 0
}

/// The block as 64-bit little-endian words.
pub(crate) fn to_words(block: &[u8]) -> Vec<u64> {
    block.chunks_exact(WORD_BYTES).map(read_u64_le).collect()
}

/// Writes 64-bit words little-endian into `block`.
pub(crate) fn write_words(words: &[u64], block: &mut [u8]) {
    for (bytes, word) in block.chunks_exact_mut(WORD_BYTES).zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut word = [0u8; WORD_BYTES];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_value_is_right_aligned_and_a_long_one_refused() {
        assert_eq!(right_aligned(&[1, 2], 4), Ok(vec![0, 0, 1, 2]));
        assert_eq!(
            right_aligned(&[0; 5], 4),
            Err(CipherFailure::IvTooLong {
                length: 5,
                block_bytes: 4
            })
        );
    }

    #[test]
    fn constant_time_equality_compares_length_and_content() {
        assert!(is_equal_in_constant_time(&[1, 2], &[1, 2]));
        assert!(!is_equal_in_constant_time(&[1, 2], &[1, 3]));
        assert!(!is_equal_in_constant_time(&[1, 2], &[1]));
    }
}
