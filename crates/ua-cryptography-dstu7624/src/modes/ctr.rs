// Translated from BouncyCastle Java 1.86 KCTRBlockCipher (MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::right_aligned;

/// Counter mode of DSTU 7624 ("гамування"): the counter starts at E(IV) and is incremented as a little-endian integer
/// before each block. Encryption and decryption are the same; any message length; a short IV is right-aligned.
#[derive(Debug, Clone)]
pub struct Ctr {
    cipher: Kalyna,
}

impl Ctr {
    /// The mode over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
        })
    }

    /// XORs the gamma into `data`: encrypts plaintext, decrypts ciphertext.
    pub fn apply_gamma(&self, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        apply_counter_gamma(&self.cipher, iv, data)
    }
}

/// The counter gamma of KCTRBlockCipher; GCM encrypts with it too.
pub(crate) fn apply_counter_gamma(cipher: &Kalyna, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
    let block_bytes = cipher.block_bytes();
    let mut counter = right_aligned(iv, block_bytes)?;
    cipher.encrypt_block(&mut counter); // S = E(IV)
    let mut result = Vec::with_capacity(data.len());
    for input in data.chunks(block_bytes) {
        increment_little_endian(&mut counter);
        let mut gamma = counter.clone();
        cipher.encrypt_block(&mut gamma);
        result.extend(
            input
                .iter()
                .zip(&gamma)
                .map(|(&source, &gamma_byte)| source ^ gamma_byte),
        );
    }
    Ok(result)
}

/// counter ← counter + 1 mod 2^n, least significant byte first.
pub(crate) fn increment_little_endian(counter: &mut [u8]) {
    for byte in counter.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}
