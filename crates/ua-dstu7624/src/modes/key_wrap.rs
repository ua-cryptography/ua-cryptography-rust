// Translated from BouncyCastle Java 1.86 DSTU7624WrapEngine (MIT, THIRD-PARTY-NOTICES.md).

use crate::BlockSize;
use crate::CipherFailure;
use crate::Kalyna;
use crate::SetupError;
use crate::utils::block_bytes::check_whole_blocks;
use crate::utils::block_bytes::is_equal_in_constant_time;

const ROUNDS_PER_HALF: usize = 6;
const COUNTER_BYTES: usize = 4;

/// Key wrapping ("захист ключів"): whole blocks; the wrapped value is one block longer, its integrity block being zero.
#[derive(Debug, Clone)]
pub struct KeyWrap {
    cipher: Kalyna,
}

impl KeyWrap {
    /// The mode over a key of one or two blocks.
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        Ok(Self {
            cipher: Kalyna::new(block_size, key)?,
        })
    }

    /// Wraps a non-empty whole number of blocks.
    pub fn wrap_key(&self, data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        let half = block_bytes / 2;
        check_whole_blocks(data.len(), block_bytes)?;
        if data.is_empty() {
            return Err(CipherFailure::EmptyMessage);
        }
        let n = 2 * (1 + data.len() / block_bytes);
        let steps = (n - 1) * ROUNDS_PER_HALF;
        // The data followed by a zero block, the integrity check.
        let mut buffer = data.to_vec();
        buffer.resize(data.len() + block_bytes, 0);
        let (first_half, rest) = buffer.split_at(half);
        let mut b_half = first_half.to_vec();
        let mut halves: Vec<Vec<u8>> = rest.chunks_exact(half).map(<[u8]>::to_vec).collect();

        let mut block = vec![0u8; block_bytes];
        for j in 0..steps {
            block[..half].copy_from_slice(&b_half);
            block[half..].copy_from_slice(&halves[0]);
            self.cipher.encrypt_block(&mut block);
            xor_counter(&mut block[half..], j + 1);
            b_half.copy_from_slice(&block[half..]);
            halves.rotate_left(1);
            halves[n - 2].copy_from_slice(&block[..half]);
        }
        Ok(join_halves(&b_half, &halves))
    }

    /// Unwraps and checks the integrity block.
    pub fn unwrap_key(&self, data: &[u8]) -> Result<Vec<u8>, CipherFailure> {
        let block_bytes = self.cipher.block_bytes();
        let half = block_bytes / 2;
        check_whole_blocks(data.len(), block_bytes)?;
        if data.len() < 2 * block_bytes {
            return Err(CipherFailure::WrappedDataTooShort);
        }
        let n = 2 * data.len() / block_bytes;
        let steps = (n - 1) * ROUNDS_PER_HALF;
        let (first_half, rest) = data.split_at(half);
        let mut b_half = first_half.to_vec();
        let mut halves: Vec<Vec<u8>> = rest.chunks_exact(half).map(<[u8]>::to_vec).collect();

        let mut block = vec![0u8; block_bytes];
        for j in 0..steps {
            block[..half].copy_from_slice(&halves[n - 2]);
            block[half..].copy_from_slice(&b_half);
            xor_counter(&mut block[half..], steps - j);
            self.cipher.decrypt_block(&mut block);
            b_half.copy_from_slice(&block[..half]);
            halves.rotate_right(1);
            halves[0].copy_from_slice(&block[half..]);
        }
        let mut buffer = join_halves(&b_half, &halves);
        let key_length = buffer.len() - block_bytes;
        if !is_equal_in_constant_time(&buffer[key_length..], &vec![0u8; block_bytes]) {
            return Err(CipherFailure::IntegrityCheckFailed);
        }
        buffer.truncate(key_length);
        Ok(buffer)
    }
}

/// XORs the 32-bit little-endian step counter into the first bytes of `target`.
fn xor_counter(target: &mut [u8], counter: usize) {
    let counter_bytes = (counter as u32).to_le_bytes();
    for (byte, counter_byte) in target[..COUNTER_BYTES].iter_mut().zip(counter_bytes) {
        *byte ^= counter_byte;
    }
}

fn join_halves(b_half: &[u8], halves: &[Vec<u8>]) -> Vec<u8> {
    let mut joined = b_half.to_vec();
    for half in halves {
        joined.extend_from_slice(half);
    }
    joined
}
