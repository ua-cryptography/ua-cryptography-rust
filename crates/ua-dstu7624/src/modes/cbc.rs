// Translated from BouncyCastle Java 1.86 (its generic CBC mode as its DSTU 7624 tests use it; MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::check_one_block_iv;
use crate::utils::block_bytes::check_whole_blocks;
use crate::utils::block_bytes::xor_into;

/// Cipher block chaining ("простої заміни з зачепленням"): whole blocks, an IV of one block.
#[derive(Debug, Clone)]
pub struct Cbc {
    cipher: Kalyna,
}

impl Cbc {
    /// The mode over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
        })
    }

    /// Encrypts whole blocks.
    pub fn encrypt(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.check_input(iv, data)?;
        let mut result = data.to_vec();
        let mut previous = iv.to_vec();
        for block in result.chunks_exact_mut(block_bytes) {
            xor_into(block, &previous);
            self.cipher.encrypt_block(block);
            previous.copy_from_slice(block);
        }
        Ok(result)
    }

    /// Decrypts whole blocks.
    pub fn decrypt(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.check_input(iv, data)?;
        let mut result = data.to_vec();
        let mut previous = iv;
        for (block, cipher_block) in result.chunks_exact_mut(block_bytes).zip(data.chunks_exact(block_bytes)) {
            self.cipher.decrypt_block(block);
            xor_into(block, previous);
            previous = cipher_block;
        }
        Ok(result)
    }

    fn check_input(&self, iv: &[u8], data: &[u8]) -> Result<usize, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        check_whole_blocks(data.len(), block_bytes)?;
        check_one_block_iv(iv, block_bytes)?;
        Ok(block_bytes)
    }
}
