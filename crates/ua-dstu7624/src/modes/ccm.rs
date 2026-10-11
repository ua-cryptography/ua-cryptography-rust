// Translated from BouncyCastle Java 1.86 KCCMBlockCipher (MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::modes::ctr::increment_little_endian;
use crate::utils::block_bytes::is_equal_in_constant_time;
use crate::utils::block_bytes::xor_into;

const BITS_PER_BYTE: usize = 8;
const DEFAULT_NB: usize = 4;
const LENGTH_FIELD_BYTES: usize = 4;
const ASSOCIATED_DATA_FLAG: u8 = 0x80;
const MAC_CODE_SHIFT: u32 = 4;

/// Authenticated encryption CCM of DSTU 7624 ("вироблення імітовставки та гамування"). Encryption outputs
/// ciphertext ‖ tag; the nonce (at most one block) is zero-padded on the right; Nb (4, 6 or 8) bounds the message
/// length; the tag is 64, 128, 256, 384 or 512 bits, at most a block.
#[derive(Debug, Clone)]
pub struct Ccm {
    cipher: Kalyna,
    nb: usize,
}

impl Ccm {
    /// The mode with Nb = 4 (messages up to 2^32 − 1 bits).
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Self::with_nb(block_size, key, DEFAULT_NB)
    }

    /// The mode with the length field Nb of 4, 6 or 8 bytes.
    pub fn with_nb(block_size: BlockSize, key: &[u8], nb: usize) -> Result<Self, SetupError> {
        if !matches!(nb, 4 | 6 | 8) {
            return Err(SetupError::UnsupportedNb { nb });
        }
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
            nb,
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
        let nonce_block = self.pad_nonce(nonce)?;
        let mac = self.calculate_mac(&nonce_block, associated_data, plain_text, mac_bytes);

        let mut counter = nonce_block;
        self.cipher.encrypt_block(&mut counter);
        let mut result = self.apply_gamma(&mut counter, plain_text);
        let gamma = self.next_gamma(&mut counter);
        result.extend(
            gamma
                .iter()
                .zip(&mac)
                .take(mac_bytes)
                .map(|(&gamma_byte, &mac_byte)| gamma_byte ^ mac_byte),
        );
        Ok(result)
    }

    /// Decrypts ciphertext ‖ tag and verifies the tag.
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
        let nonce_block = self.pad_nonce(nonce)?;
        let (body, masked_tag) = cipher_text.split_at(cipher_text.len() - mac_bytes);

        let mut counter = nonce_block.clone();
        self.cipher.encrypt_block(&mut counter);
        let mut plain_text = self.apply_gamma(&mut counter, body);
        let gamma = self.next_gamma(&mut counter);
        let received_tag: Vec<u8> = gamma
            .iter()
            .zip(masked_tag)
            .map(|(&gamma_byte, &tag_byte)| gamma_byte ^ tag_byte)
            .collect();

        let expected = self.calculate_mac(&nonce_block, associated_data, &plain_text, mac_bytes);
        if !is_equal_in_constant_time(&expected[..mac_bytes], &received_tag) {
            plain_text.fill(0);
            return Err(CipherFailure::TagMismatch);
        }
        Ok(plain_text)
    }

    /// The tag length in bytes: 64, 128, 256, 384 or 512 bits, at most a block.
    fn mac_bytes_of(&self, mac_bits: usize) -> Result<usize, CipherFailure> {
        let is_supported =
            matches!(mac_bits, 64 | 128 | 256 | 384 | 512) && mac_bits <= self.cipher.block_size().bits();
        if !is_supported {
            return Err(CipherFailure::UnsupportedMacLength { bits: mac_bits });
        }
        Ok(mac_bits / BITS_PER_BYTE)
    }

    /// The nonce left-aligned in a zero block.
    fn pad_nonce(&self, nonce: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        if nonce.len() > block_bytes {
            return Err(CipherFailure::IvTooLong {
                length: nonce.len(),
                block_bytes,
            });
        }
        let mut block = vec![0u8; block_bytes];
        block[..nonce.len()].copy_from_slice(nonce);
        Ok(block)
    }

    fn apply_gamma(&self, counter: &mut [u8], data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        for input in data.chunks(self.cipher.block_bytes()) {
            let gamma = self.next_gamma(counter);
            result.extend(
                input
                    .iter()
                    .zip(&gamma)
                    .map(|(&source, &gamma_byte)| source ^ gamma_byte),
            );
        }
        result
    }

    /// s ← s + 1 (little-endian), gamma = E(s).
    fn next_gamma(&self, counter: &mut [u8]) -> Vec<u8> {
        increment_little_endian(counter);
        let mut gamma = counter.to_vec();
        self.cipher.encrypt_block(&mut gamma);
        gamma
    }

    /// The CBC-MAC over G1 (nonce, length, flags), the associated data and the plaintext.
    fn calculate_mac(
        &self,
        nonce_block: &[u8],
        associated_data: &[u8],
        plain_text: &[u8],
        mac_bytes: usize,
    ) -> Vec<u8> {
        let block_bytes = self.cipher.block_bytes();
        let has_associated_data = !associated_data.is_empty();
        let length_offset = block_bytes - self.nb - 1;

        let mut mac = vec![0u8; block_bytes];
        mac[..length_offset].copy_from_slice(&nonce_block[..length_offset]);
        mac[length_offset..][..LENGTH_FIELD_BYTES].copy_from_slice(&length_field_of(plain_text));
        mac[block_bytes - 1] = self.flags_of(has_associated_data, mac_bytes);
        self.cipher.encrypt_block(&mut mac);

        if has_associated_data {
            let mut g2 = vec![0u8; block_bytes];
            g2[..LENGTH_FIELD_BYTES].copy_from_slice(&length_field_of(associated_data));
            let fits_in_g2 = associated_data.len() <= block_bytes - self.nb;
            if fits_in_g2 {
                xor_into(&mut g2[self.nb..self.nb + associated_data.len()], associated_data);
            }
            xor_into(&mut mac, &g2);
            self.cipher.encrypt_block(&mut mac);
            if !fits_in_g2 {
                self.absorb(&mut mac, associated_data);
            }
        }

        self.absorb(&mut mac, plain_text);
        mac
    }

    /// CBC-MAC over the blocks of `data`; a trailing partial block is zero-padded.
    fn absorb(&self, mac: &mut [u8], data: &[u8]) {
        for chunk in data.chunks(self.cipher.block_bytes()) {
            xor_into(&mut mac[..chunk.len()], chunk);
            self.cipher.encrypt_block(mac);
        }
    }

    /// The flags byte of G1: associated data present (bit 7), the tag length code (bits 6..4), Nb − 1 (bits 3..0).
    fn flags_of(&self, has_associated_data: bool, mac_bytes: usize) -> u8 {
        let mac_code: u8 = match mac_bytes {
            8 => 2,
            16 => 3,
            32 => 4,
            48 => 5,
            _ => 6,
        };
        let associated_data_flag = if has_associated_data { ASSOCIATED_DATA_FLAG } else { 0 };
        associated_data_flag | (mac_code << MAC_CODE_SHIFT) | (self.nb - 1) as u8
    }
}

/// A length as KCCMBlockCipher writes it: 32 bits, little-endian.
fn length_field_of(data: &[u8]) -> [u8; LENGTH_FIELD_BYTES] {
    (data.len() as u32).to_le_bytes()
}
