// Translated from BouncyCastle Java 1.86 (its generic ECB mode as its DSTU 7624 tests use it; MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::check_whole_blocks;

/// Electronic codebook ("простої заміни"): whole blocks only.
#[derive(Debug, Clone)]
pub struct Ecb {
    cipher: Kalyna,
}

impl Ecb {
    /// The mode over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
        })
    }

    /// Encrypts whole blocks.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        self.transform(data, Kalyna::encrypt_block)
    }

    /// Decrypts whole blocks.
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        self.transform(data, Kalyna::decrypt_block)
    }

    fn transform(&self, data: &[u8], transform_block: fn(&Kalyna, &mut [u8])) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        check_whole_blocks(data.len(), block_bytes)?;
        let mut result = data.to_vec();
        for block in result.chunks_exact_mut(block_bytes) {
            transform_block(&self.cipher, block);
        }
        Ok(result)
    }
}
