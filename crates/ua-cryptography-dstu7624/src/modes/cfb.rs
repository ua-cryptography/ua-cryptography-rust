// Translated from BouncyCastle Java 1.86 (its generic CFB mode as its DSTU 7624 tests use it; MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::right_aligned;
use crate::utils::segment::segment_bytes_of;

/// Cipher feedback ("гамування зі зворотним зв'язком за шифрограмою") with an s-bit segment, 8 ≤ s ≤ block, a
/// multiple of 8. Any message length; a short IV is right-aligned in a zero block.
#[derive(Debug, Clone)]
pub struct Cfb {
    cipher: Kalyna,
    segment_bytes: usize,
}

impl Cfb {
    /// The mode with a segment of one block.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Self::with_segment(block_size, key, block_size.bits())
    }

    /// The mode with a segment of `segment_bits`.
    pub fn with_segment(block_size: BlockSize, key: &[u8], segment_bits: usize) -> Result<Self, SetupError> {
        let segment_bytes = segment_bytes_of(segment_bits, block_size)?;
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
            segment_bytes,
        })
    }

    /// Encrypts a message of any length.
    pub fn encrypt(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        self.transform(iv, data, true)
    }

    /// Decrypts a message of any length.
    pub fn decrypt(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        self.transform(iv, data, false)
    }

    fn transform(&self, iv: &[u8], data: &[u8], is_encryption: bool) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        let segment_bytes = self.segment_bytes;
        let mut register = right_aligned(iv, block_bytes)?;
        let mut result = vec![0u8; data.len()];
        for (segment_index, input) in data.chunks(segment_bytes).enumerate() {
            let position = segment_index * segment_bytes;
            let mut gamma = register.clone();
            self.cipher.encrypt_block(&mut gamma);
            let output = &mut result[position..position + input.len()];
            for ((target, &source), &gamma_byte) in output.iter_mut().zip(input).zip(&gamma) {
                *target = source ^ gamma_byte;
            }
            // The register shifts left by one segment and takes in the ciphertext.
            let cipher_text: &[u8] = if is_encryption { output } else { input };
            register.copy_within(segment_bytes.., 0);
            register[block_bytes - segment_bytes..][..cipher_text.len()].copy_from_slice(cipher_text);
        }
        Ok(result)
    }
}
