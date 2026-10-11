// Translated from BouncyCastle Java 1.86 DSTU7624Mac (MIT, THIRD-PARTY-NOTICES.md).

use std::fmt;

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::check_whole_blocks;
use crate::utils::block_bytes::xor_into;

const BITS_PER_BYTE: usize = 8;

/// The MAC of DSTU 7624 ("вироблення імітовставки"): a CBC-MAC whose last block is masked with E(0). The message is a
/// non-empty whole number of blocks; the MAC length is a multiple of 8 bits up to the block length.
#[derive(Clone)]
pub struct Cmac {
    cipher: Kalyna,
    mac_bytes: usize,
    delta: Vec<u8>,
}

impl Cmac {
    /// The MAC of `mac_bits` bits over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8], mac_bits: usize) -> Result<Self, SetupError> {
        let is_supported = mac_bits >= BITS_PER_BYTE && mac_bits <= block_size.bits() && mac_bits % BITS_PER_BYTE == 0;
        if !is_supported {
            return Err(SetupError::UnsupportedMacLength { bits: mac_bits });
        }
        let cipher = Kalyna::new(block_size, key)?;
        let mut delta = vec![0u8; cipher.block_bytes()];
        cipher.encrypt_block(&mut delta); // kDelta = E(0)
        Ok(Self {
            cipher,
            mac_bytes: mac_bits / BITS_PER_BYTE,
            delta,
        })
    }

    /// The MAC of a non-empty whole number of blocks.
    pub fn calculate_mac(&self, data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        if data.is_empty() {
            return Err(CipherFailure::EmptyMessage);
        }
        check_whole_blocks(data.len(), block_bytes)?;
        let mut chain = vec![0u8; block_bytes];
        let block_count = data.len() / block_bytes;
        for (index, block) in data.chunks_exact(block_bytes).enumerate() {
            xor_into(&mut chain, block);
            if index + 1 == block_count {
                xor_into(&mut chain, &self.delta);
            }
            self.cipher.encrypt_block(&mut chain);
        }
        chain.truncate(self.mac_bytes);
        Ok(chain)
    }
}

impl fmt::Debug for Cmac {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cmac")
            .field("mac_bytes", &self.mac_bytes)
            .finish_non_exhaustive()
    }
}
