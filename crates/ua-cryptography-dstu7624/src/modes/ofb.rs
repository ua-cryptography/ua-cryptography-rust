// Translated from BouncyCastle Java 1.86 (its generic OFB mode as its DSTU 7624 tests use it; MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::right_aligned;
use crate::utils::segment::segment_bytes_of;

/// Output feedback ("гамування зі зворотним зв'язком за гамою") with an s-bit segment. Encryption and decryption are
/// the same operation; any message length; a short IV is right-aligned in a zero block.
#[derive(Debug, Clone)]
pub struct Ofb {
    cipher: Kalyna,
    segment_bytes: usize,
}

impl Ofb {
    /// The mode with a segment of one block.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Self::with_segment(block_size, key, block_size.bits())
    }

    /// The mode with a segment of `segment_bits`, a multiple of 8 from 8 to the block length.
    pub fn with_segment(block_size: BlockSize, key: &[u8], segment_bits: usize) -> Result<Self, SetupError> {
        let segment_bytes = segment_bytes_of(segment_bits, block_size)?;
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
            segment_bytes,
        })
    }

    /// XORs the gamma into `data`: encrypts plaintext, decrypts ciphertext.
    pub fn apply_gamma(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        let segment_bytes = self.segment_bytes;
        let mut register = right_aligned(iv, block_bytes)?;
        let mut result = Vec::with_capacity(data.len());
        for input in data.chunks(segment_bytes) {
            let mut gamma = register.clone();
            self.cipher.encrypt_block(&mut gamma);
            result.extend(
                input
                    .iter()
                    .zip(&gamma)
                    .map(|(&source, &gamma_byte)| source ^ gamma_byte),
            );
            // The register shifts left by one segment and takes in the gamma.
            register.copy_within(segment_bytes.., 0);
            register[block_bytes - segment_bytes..].copy_from_slice(&gamma[..segment_bytes]);
        }
        Ok(result)
    }
}
