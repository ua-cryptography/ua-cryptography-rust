// Translated from BouncyCastle Java 1.86 KXTSBlockCipher (MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::check_one_block_iv;
use crate::utils::block_bytes::check_whole_blocks;
use crate::utils::block_bytes::to_words;
use crate::utils::block_bytes::write_words;
use crate::utils::block_bytes::xor_into;
use crate::utils::galois_field::multiply_by_x;
use crate::utils::galois_field::reduction_of;

/// XTS ("індексована заміна"): whole blocks; the tweak E(IV) is multiplied by x in GF(2^n) (the polynomials of GCM)
/// before each block. The IV is exactly one block; one key serves the tweak and the data.
#[derive(Debug, Clone)]
pub struct Xts {
    cipher: Kalyna,
    reduction: u64,
}

impl Xts {
    /// The mode over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
            reduction: reduction_of(block_size),
        })
    }

    /// Encrypts whole blocks under the tweak IV.
    pub fn encrypt(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        self.transform(iv, data, Kalyna::encrypt_block)
    }

    /// Decrypts whole blocks under the tweak IV.
    pub fn decrypt(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        self.transform(iv, data, Kalyna::decrypt_block)
    }

    fn transform(
        &self,
        iv: &[u8],
        data: &[u8],
        transform_block: fn(&Kalyna, &mut [u8]),
    ) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        check_one_block_iv(iv, block_bytes)?;
        check_whole_blocks(data.len(), block_bytes)?;

        let mut tweak_bytes = iv.to_vec();
        self.cipher.encrypt_block(&mut tweak_bytes);
        let mut tweak = to_words(&tweak_bytes);
        let mut result = data.to_vec();
        for block in result.chunks_exact_mut(block_bytes) {
            multiply_by_x(&mut tweak, self.reduction);
            write_words(&tweak, &mut tweak_bytes);
            xor_into(block, &tweak_bytes);
            transform_block(&self.cipher, block);
            xor_into(block, &tweak_bytes);
        }
        Ok(result)
    }
}
