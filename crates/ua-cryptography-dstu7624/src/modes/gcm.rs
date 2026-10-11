// Translated from BouncyCastle Java 1.86 KGCMBlockCipher (MIT, THIRD-PARTY-NOTICES.md).

use std::fmt;

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::modes::ctr::apply_counter_gamma;
use crate::utils::block_bytes::is_equal_in_constant_time;
use crate::utils::block_bytes::right_aligned;
use crate::utils::block_bytes::to_words;
use crate::utils::block_bytes::write_words;
use crate::utils::galois_field::multiply;
use crate::utils::galois_field::reduction_of;

const BITS_PER_BYTE: usize = 8;
const MIN_MAC_BITS: usize = 64;
const BIT_LENGTH_SHIFT: u32 = 3;

/// Authenticated encryption GCM of DSTU 7624: the counter mode of [`crate::Ctr`] and a GHASH in GF(2^128), GF(2^256)
/// or GF(2^512) over little-endian words. Encryption outputs ciphertext ‖ tag; the nonce (at most one block) is
/// right-aligned in a zero block; the tag is 64 bits to a block, a multiple of 8.
#[derive(Clone)]
pub struct Gcm {
    cipher: Kalyna,
    hash_key: Vec<u64>,
    reduction: u64,
}

impl Gcm {
    /// The mode over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        let cipher = Kalyna::new(block_size, key)?;
        let mut zero_block = vec![0u8; cipher.block_bytes()];
        cipher.encrypt_block(&mut zero_block); // H = E(0)
        Ok(Self {
            cipher,
            hash_key: to_words(&zero_block),
            reduction: reduction_of(block_size),
        })
    }

    /// Encrypts `plain_text` and tags it with `associated_data`; returns ciphertext ‖ tag of `mac_bits`.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        plain_text: &[u8],
        mac_bits: usize,
    ) -> Result<Vec<u8>, CipherFailure> {
        let mac_bytes = self.mac_bytes_of(mac_bits)?;
        let nonce_block = right_aligned(nonce, self.cipher.block_bytes())?;
        let mut result = apply_counter_gamma(&self.cipher, &nonce_block, plain_text)?;
        let tag = self.calculate_tag(associated_data, &result);
        result.extend_from_slice(&tag[..mac_bytes]);
        Ok(result)
    }

    /// Verifies the tag of ciphertext ‖ tag, then decrypts.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        associated_data: &[u8],
        cipher_text: &[u8],
        mac_bits: usize,
    ) -> Result<Vec<u8>, CipherFailure> {
        let mac_bytes = self.mac_bytes_of(mac_bits)?;
        if cipher_text.len() < mac_bytes {
            return Err(CipherFailure::CiphertextShorterThanTag);
        }
        let (body, received_tag) = cipher_text.split_at(cipher_text.len() - mac_bytes);
        let tag = self.calculate_tag(associated_data, body);
        if !is_equal_in_constant_time(&tag[..mac_bytes], received_tag) {
            return Err(CipherFailure::TagMismatch);
        }
        let nonce_block = right_aligned(nonce, self.cipher.block_bytes())?;
        apply_counter_gamma(&self.cipher, &nonce_block, body)
    }

    /// The tag length in bytes: 64 bits to a block, a multiple of 8.
    fn mac_bytes_of(&self, mac_bits: usize) -> Result<usize, CipherFailure> {
        let is_supported =
            mac_bits >= MIN_MAC_BITS && mac_bits <= self.cipher.block_size().bits() && mac_bits % BITS_PER_BYTE == 0;
        if !is_supported {
            return Err(CipherFailure::UnsupportedMacLength { bits: mac_bits });
        }
        Ok(mac_bits / BITS_PER_BYTE)
    }

    /// E(GHASH(A, C) with the bit lengths of A and C added to words 0 and n/2).
    fn calculate_tag(&self, associated_data: &[u8], cipher_text: &[u8]) -> Vec<u8> {
        let words = self.hash_key.len();
        let mut accumulator = vec![0u64; words];
        self.absorb(&mut accumulator, associated_data);
        self.absorb(&mut accumulator, cipher_text);
        accumulator[0] ^= bit_length_of(associated_data);
        accumulator[words / 2] ^= bit_length_of(cipher_text);

        let mut tag = vec![0u8; self.cipher.block_bytes()];
        write_words(&accumulator, &mut tag);
        self.cipher.encrypt_block(&mut tag);
        tag
    }

    /// x ← (x ⊕ block)·H for every block; a trailing partial block is zero-padded.
    fn absorb(&self, accumulator: &mut Vec<u64>, data: &[u8]) {
        let block_bytes = self.cipher.block_bytes();
        for chunk in data.chunks(block_bytes) {
            let mut block = vec![0u8; block_bytes];
            block[..chunk.len()].copy_from_slice(chunk);
            for (word, block_word) in accumulator.iter_mut().zip(to_words(&block)) {
                *word ^= block_word;
            }
            *accumulator = multiply(accumulator, &self.hash_key, self.reduction);
        }
    }
}

impl fmt::Debug for Gcm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Gcm")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

/// The length in bits of a message shorter than 2^32 bytes, as KGCMBlockCipher counts it.
fn bit_length_of(data: &[u8]) -> u64 {
    u64::from(data.len() as u32) << BIT_LENGTH_SHIFT
}
