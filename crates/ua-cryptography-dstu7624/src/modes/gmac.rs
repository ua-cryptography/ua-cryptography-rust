// Translated from BouncyCastle Java 1.86 KGMac (MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Gcm;
use crate::SetupError;

/// GMAC of DSTU 7624: GCM with an empty plaintext, the message being the associated data.
#[derive(Debug, Clone)]
pub struct Gmac {
    gcm: Gcm,
}

impl Gmac {
    /// The MAC over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Ok(Self {
            gcm: Gcm::new(block_size, key)?,
        })
    }

    /// The MAC of `mac_bits` (64 to a block, a multiple of 8) over `data` under `nonce`.
    pub fn calculate_mac(&self, nonce: &[u8], data: &[u8], mac_bits: usize) -> Result<Vec<u8>, CipherFailure> {
        self.gcm.encrypt(nonce, data, &[], mac_bits)
    }
}
