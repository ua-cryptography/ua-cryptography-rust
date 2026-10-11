use std::fmt;

use crate::DEFAULT_DKE;
use crate::Gost28147;
use crate::SubstitutionTableError;
use crate::gost28147::expand_checked_dke;

const HASH_BYTES: usize = 32;
const SUBBLOCK_BYTES: usize = 8;
const SUBBLOCK_COUNT: usize = 4;
const BITS_PER_BYTE: u64 = 8;
const LENGTH_FIELD_BYTES: usize = 8;
const BYTE_BITS: u32 = 8;
// The constant C3 of the key generation; C2 and C4 are zero.
const C3: [u8; HASH_BYTES] = [
    0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, //
    0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF, //
];
const C3_ROUND: usize = 2;
const PSI_ROUNDS_BEFORE_MESSAGE: usize = 12;
const PSI_ROUNDS_AFTER_HASH: usize = 61;

/// GOST 34.311-95 hash function (the Ukrainian adoption of GOST R 34.11-94), the default hash of DSTU 4145-2002 (6.2).
///
/// The 32-byte result is the hash value H as GOST defines it, least significant byte first; the binary string
/// (h_255, …, h_0) of DSTU 4145-2002 (5.6, 5.9) is the reversed array. The substitution table is a parameter:
/// Ukrainian certificates carry it as a 64-byte DKE, and [`DEFAULT_DKE`] is the one used when none is given.
#[derive(Clone)]
pub struct Gost34311 {
    cipher: Gost28147,
    initial_value: [u8; HASH_BYTES],
    hash: [u8; HASH_BYTES],
    control_sum: [u8; HASH_BYTES],
    buffer: [u8; HASH_BYTES],
    buffer_length: usize,
    message_bytes: u64,
}

impl Gost34311 {
    /// The hash length in bytes.
    pub const HASH_BYTES: usize = HASH_BYTES;

    /// The hash with a 128-entry substitution table (see [`Gost28147::new`]) and a zero initial value.
    pub fn new(sbox: &[u8]) -> Result<Self, SubstitutionTableError> {
        Self::with_initial_value(sbox, &[0; HASH_BYTES])
    }

    /// The hash with a 128-entry substitution table and the initial hash value H0.
    pub fn with_initial_value(sbox: &[u8], initial_value: &[u8; HASH_BYTES]) -> Result<Self, SubstitutionTableError> {
        Ok(Self::from_cipher(Gost28147::new(sbox)?, initial_value))
    }

    /// The hash with the substitution table given as a 64-byte DKE, e.g. one taken from a certificate.
    pub fn from_dke(dke: &[u8]) -> Result<Self, SubstitutionTableError> {
        let sbox = Gost28147::expand_dke(dke)?;
        Ok(Self::from_cipher(Gost28147::from_checked_sbox(&sbox), &[0; HASH_BYTES]))
    }

    /// One-shot hash with [`DEFAULT_DKE`].
    pub fn calculate_hash(data: &[u8]) -> [u8; HASH_BYTES] {
        Self::default().hash(data)
    }

    /// Starts over, absorbs `data` and returns its hash; the instance is ready for the next message.
    pub fn hash(&mut self, data: &[u8]) -> [u8; HASH_BYTES] {
        self.reset();
        self.update(data);
        self.finalize()
    }

    /// Returns to the initial value, forgetting what was absorbed.
    pub fn reset(&mut self) {
        self.hash = self.initial_value;
        self.control_sum = [0; HASH_BYTES];
        self.buffer = [0; HASH_BYTES];
        self.buffer_length = 0;
        self.message_bytes = 0;
    }

    /// Absorbs the next part of the message.
    pub fn update(&mut self, data: &[u8]) {
        self.message_bytes = self.message_bytes.wrapping_add(data.len() as u64);
        let mut rest = data;
        while !rest.is_empty() {
            let taken = (HASH_BYTES - self.buffer_length).min(rest.len());
            self.buffer[self.buffer_length..][..taken].copy_from_slice(&rest[..taken]);
            self.buffer_length += taken;
            rest = &rest[taken..];
            if self.buffer_length == HASH_BYTES {
                self.absorb_buffer();
            }
        }
    }

    /// Returns the hash of everything absorbed and resets to the initial value.
    pub fn finalize(&mut self) -> [u8; HASH_BYTES] {
        if self.buffer_length > 0 {
            // The last block is padded with zeros; the length counts only the real message bits.
            self.buffer[self.buffer_length..].fill(0);
            self.absorb_buffer();
        }
        let mut length_block = [0u8; HASH_BYTES];
        let message_bits = self.message_bytes.wrapping_mul(BITS_PER_BYTE); // messages up to 2^61 bytes
        length_block[..LENGTH_FIELD_BYTES].copy_from_slice(&message_bits.to_le_bytes());
        self.step(&length_block);
        let control_sum = self.control_sum;
        self.step(&control_sum);
        let result = self.hash;
        self.reset();
        result
    }

    fn from_cipher(cipher: Gost28147, initial_value: &[u8; HASH_BYTES]) -> Self {
        let mut hasher = Self {
            cipher,
            initial_value: *initial_value,
            hash: *initial_value,
            control_sum: [0; HASH_BYTES],
            buffer: [0; HASH_BYTES],
            buffer_length: 0,
            message_bytes: 0,
        };
        hasher.reset();
        hasher
    }

    fn absorb_buffer(&mut self) {
        let block = self.buffer;
        add_to_control_sum(&mut self.control_sum, &block);
        self.step(&block);
        self.buffer_length = 0;
    }

    /// The step function H = χ(M, H): key generation, encryption, mixing.
    fn step(&mut self, message_block: &[u8; HASH_BYTES]) {
        let mut u = self.hash;
        let mut v = *message_block;
        let mut s = [0u8; HASH_BYTES];
        for i in 0..SUBBLOCK_COUNT {
            if i > 0 {
                transform_a(&mut u);
                if i == C3_ROUND {
                    xor_into(&mut u, &C3);
                }
                transform_a(&mut v);
                transform_a(&mut v);
            }
            let mut w = u;
            xor_into(&mut w, &v);
            self.cipher.set_key(&permute_p(&w));
            let hash_subblock = subblock(&self.hash, i);
            let encrypted = self.cipher.encrypt_block(&hash_subblock); // s_i = E_Ki(h_i)
            s[SUBBLOCK_BYTES * i..][..SUBBLOCK_BYTES].copy_from_slice(&encrypted);
        }

        // H = ψ^61(H ⊕ ψ(M ⊕ ψ^12(S)))
        for _ in 0..PSI_ROUNDS_BEFORE_MESSAGE {
            transform_psi(&mut s);
        }
        xor_into(&mut s, message_block);
        transform_psi(&mut s);
        xor_into(&mut s, &self.hash);
        for _ in 0..PSI_ROUNDS_AFTER_HASH {
            transform_psi(&mut s);
        }
        self.hash = s;
    }
}

impl Default for Gost34311 {
    /// The hash with [`DEFAULT_DKE`] and a zero initial value.
    fn default() -> Self {
        let sbox = expand_checked_dke(&DEFAULT_DKE);
        Self::from_cipher(Gost28147::from_checked_sbox(&sbox), &[0; HASH_BYTES])
    }
}

impl fmt::Debug for Gost34311 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Gost34311").finish_non_exhaustive()
    }
}

/// Σ = Σ + M mod 2^256, little-endian.
fn add_to_control_sum(control_sum: &mut [u8; HASH_BYTES], block: &[u8; HASH_BYTES]) {
    let mut carry = 0u16;
    for (sum_byte, &block_byte) in control_sum.iter_mut().zip(block) {
        let total = u16::from(*sum_byte) + u16::from(block_byte) + carry;
        *sum_byte = total as u8;
        carry = total >> BYTE_BITS;
    }
}

fn xor_into(target: &mut [u8; HASH_BYTES], other: &[u8; HASH_BYTES]) {
    for (target_byte, &other_byte) in target.iter_mut().zip(other) {
        *target_byte ^= other_byte;
    }
}

fn subblock(value: &[u8; HASH_BYTES], index: usize) -> [u8; SUBBLOCK_BYTES] {
    let mut block = [0u8; SUBBLOCK_BYTES];
    block.copy_from_slice(&value[SUBBLOCK_BYTES * index..][..SUBBLOCK_BYTES]);
    block
}

/// A(y4 ‖ y3 ‖ y2 ‖ y1) = (y1 ⊕ y2) ‖ y4 ‖ y3 ‖ y2 (64-bit blocks, y1 first in memory).
fn transform_a(y: &mut [u8; HASH_BYTES]) {
    let mut top = [0u8; SUBBLOCK_BYTES];
    for (j, byte) in top.iter_mut().enumerate() {
        *byte = y[j] ^ y[j + SUBBLOCK_BYTES];
    }
    y.copy_within(SUBBLOCK_BYTES.., 0);
    y[HASH_BYTES - SUBBLOCK_BYTES..].copy_from_slice(&top);
}

/// The byte permutation φ(i + 1 + 4(k − 1)) = 8i + k.
fn permute_p(w: &[u8; HASH_BYTES]) -> [u8; HASH_BYTES] {
    let mut key = [0u8; HASH_BYTES];
    for k in 0..SUBBLOCK_BYTES {
        for i in 0..SUBBLOCK_COUNT {
            key[SUBBLOCK_COUNT * k + i] = w[SUBBLOCK_BYTES * i + k];
        }
    }
    key
}

/// ψ: shifts the sixteen 16-bit words; the new top word is the XOR of words 1, 2, 3, 4, 13 and 16.
fn transform_psi(y: &mut [u8; HASH_BYTES]) {
    let low = y[0] ^ y[2] ^ y[4] ^ y[6] ^ y[24] ^ y[30];
    let high = y[1] ^ y[3] ^ y[5] ^ y[7] ^ y[25] ^ y[31];
    y.copy_within(2.., 0);
    y[HASH_BYTES - 2] = low;
    y[HASH_BYTES - 1] = high;
}
