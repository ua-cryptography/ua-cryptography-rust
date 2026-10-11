//! DSTU 7564:2014 "Kupyna".

use ua_cryptography_dstu7564::{HashSize, Kupyna};

use crate::errors::OperationFailure;

/// The hash of 256, 384 or 512 bits.
pub fn calculate_hash(data: &[u8], hash_bits: u32) -> Result<Vec<u8>, OperationFailure> {
    Ok(create_hash(hash_bits)?.hash(data))
}

/// The hash of 256, 384 or 512 bits, ready for a message fed in parts.
pub fn create_hash(hash_bits: u32) -> Result<Kupyna, OperationFailure> {
    Ok(Kupyna::new(HashSize::from_bits(hash_bits as usize)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_is_kupyna_of_the_size_asked() {
        let hash = calculate_hash(b"message", 384).unwrap();
        assert_eq!(hash, Kupyna::calculate_hash(b"message", HashSize::Bits384));
    }

    #[test]
    fn another_size_is_refused() {
        assert!(calculate_hash(b"message", 128).is_err());
    }
}
