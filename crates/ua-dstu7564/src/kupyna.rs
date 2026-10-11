use std::fmt;

use crate::HashSize;
use crate::round_tables::ROUND_TABLES;
use crate::round_tables::ROWS;

const MAX_COLUMNS: usize = 16;
const COLUMN_BYTES: usize = 8;
const MAX_BLOCK_BYTES: usize = MAX_COLUMNS * COLUMN_BYTES;
const SHORT_STATE_COLUMNS: usize = 8;
const LONG_STATE_COLUMNS: usize = 16;
const SHORT_STATE_ROUNDS: usize = 10;
const LONG_STATE_ROUNDS: usize = 14;
// ShiftBytes moves row r by r columns, except the last row of the 1024-bit state, which moves by 11.
const LONG_STATE_LAST_ROW_SHIFT: usize = 11;
const PADDING_START: u8 = 0x80;
// The message length in bits is a 96-bit little-endian number at the end of the last block.
const LENGTH_FIELD_BYTES: usize = 12;
const LENGTH_LOW_BYTES: usize = 8;
const BITS_PER_BYTE_SHIFT: u32 = 3;
const LENGTH_HIGH_SHIFT: u32 = 61;
const ROUND_CONSTANT_COLUMN_SHIFT: u32 = 4;
// T+ adds 00F0F0F0F0F0F0F3 to every column, with the column and round number in row 7.
const ADDITIVE_CONSTANT: u64 = 0x00F0_F0F0_F0F0_F0F3;
const ADDITIVE_CONSTANT_ROW_SHIFT: u32 = 56;
const BYTE_BITS: usize = 8;
const BYTE_MASK: u64 = 0xFF;

/// The DSTU 7564:2014 "Kupyna" hash function.
///
/// The state is an 8 × c byte matrix stored as c 64-bit columns (byte r of a column is row r): c = 8 and 10 rounds
/// for 256 bits, c = 16 and 14 rounds for 384 and 512. A block M updates the state as H = T⊕(H ⊕ M) ⊕ T+(M) ⊕ H, and
/// the hash is the tail of T⊕(H) ⊕ H.
#[derive(Clone)]
pub struct Kupyna {
    size: HashSize,
    columns: usize,
    rounds: usize,
    state: [u64; MAX_COLUMNS],
    buffer: [u8; MAX_BLOCK_BYTES],
    buffer_length: usize,
    message_bytes: u64,
}

impl Kupyna {
    /// The hash of the given length, ready for a message.
    pub fn new(size: HashSize) -> Self {
        let is_short_state = size == HashSize::Bits256;
        let mut hasher = Self {
            size,
            columns: if is_short_state {
                SHORT_STATE_COLUMNS
            } else {
                LONG_STATE_COLUMNS
            },
            rounds: if is_short_state {
                SHORT_STATE_ROUNDS
            } else {
                LONG_STATE_ROUNDS
            },
            state: [0; MAX_COLUMNS],
            buffer: [0; MAX_BLOCK_BYTES],
            buffer_length: 0,
            message_bytes: 0,
        };
        hasher.reset();
        hasher
    }

    /// One-shot hash of `data`.
    pub fn calculate_hash(data: &[u8], size: HashSize) -> Vec<u8> {
        Self::new(size).hash(data)
    }

    /// The length of the hashes this instance produces.
    pub fn size(&self) -> HashSize {
        self.size
    }

    /// Starts over, absorbs `data` and returns its hash; the instance is ready for the next message.
    pub fn hash(&mut self, data: &[u8]) -> Vec<u8> {
        self.reset();
        self.update(data);
        self.finalize()
    }

    /// Returns to the initial value, forgetting what was absorbed.
    pub fn reset(&mut self) {
        self.state = [0; MAX_COLUMNS];
        // The initial value: the block length in bytes in the first byte.
        self.state[0] = self.block_bytes() as u64;
        self.buffer_length = 0;
        self.message_bytes = 0;
    }

    /// Absorbs the next part of the message.
    pub fn update(&mut self, data: &[u8]) {
        let block_bytes = self.block_bytes();
        self.message_bytes = self.message_bytes.wrapping_add(data.len() as u64);
        let mut rest = data;
        while !rest.is_empty() {
            let taken = (block_bytes - self.buffer_length).min(rest.len());
            self.buffer[self.buffer_length..][..taken].copy_from_slice(&rest[..taken]);
            self.buffer_length += taken;
            rest = &rest[taken..];
            if self.buffer_length == block_bytes {
                self.absorb_buffer();
            }
        }
    }

    /// Returns the hash of everything absorbed and resets to the initial value.
    pub fn finalize(&mut self) -> Vec<u8> {
        self.absorb_padding();

        // H = T⊕(H) ⊕ H; the hash is its last n bits.
        let columns = self.columns;
        let mut permuted = self.state;
        self.permute_xor(&mut permuted);
        for (column, permuted_column) in self.state[..columns].iter_mut().zip(&permuted) {
            *column ^= permuted_column;
        }
        let first_column = columns - self.size.bytes() / COLUMN_BYTES;
        let result = self.state[first_column..columns]
            .iter()
            .flat_map(|column| column.to_le_bytes())
            .collect();
        self.reset();
        result
    }

    fn block_bytes(&self) -> usize {
        self.columns * COLUMN_BYTES
    }

    /// A single 1 bit (0x80), zeros, and the message length in bits as a 96-bit little-endian number.
    fn absorb_padding(&mut self) {
        let block_bytes = self.block_bytes();
        self.buffer[self.buffer_length] = PADDING_START;
        self.buffer_length += 1;
        if self.buffer_length > block_bytes - LENGTH_FIELD_BYTES {
            self.buffer[self.buffer_length..block_bytes].fill(0);
            self.absorb_buffer();
        }
        self.buffer[self.buffer_length..block_bytes].fill(0);
        let length_field = &mut self.buffer[block_bytes - LENGTH_FIELD_BYTES..block_bytes];
        let low_bits = self.message_bytes << BITS_PER_BYTE_SHIFT;
        let high_bits = (self.message_bytes >> LENGTH_HIGH_SHIFT) as u32;
        length_field[..LENGTH_LOW_BYTES].copy_from_slice(&low_bits.to_le_bytes());
        length_field[LENGTH_LOW_BYTES..].copy_from_slice(&high_bits.to_le_bytes());
        self.absorb_buffer();
    }

    /// H = T⊕(H ⊕ M) ⊕ T+(M) ⊕ H.
    fn absorb_buffer(&mut self) {
        let columns = self.columns;
        let mut xor_input = [0u64; MAX_COLUMNS];
        let mut add_input = [0u64; MAX_COLUMNS];
        for (c, bytes) in self.buffer[..self.block_bytes()].chunks_exact(COLUMN_BYTES).enumerate() {
            let message_column = read_u64_le(bytes);
            xor_input[c] = self.state[c] ^ message_column;
            add_input[c] = message_column;
        }
        self.permute_xor(&mut xor_input);
        self.permute_add(&mut add_input);
        for c in 0..columns {
            self.state[c] ^= xor_input[c] ^ add_input[c];
        }
        self.buffer_length = 0;
    }

    /// T⊕: the round constant of column j, (j << 4) ⊕ round, is XORed into row 0.
    fn permute_xor(&self, state: &mut [u64; MAX_COLUMNS]) {
        for round in 0..self.rounds {
            for (c, column) in state[..self.columns].iter_mut().enumerate() {
                *column ^= ((c << ROUND_CONSTANT_COLUMN_SHIFT) ^ round) as u64;
            }
            self.apply_round(state);
        }
    }

    /// T+: column j is increased mod 2^64 by 00F0F0F0F0F0F0F3 with ((c − 1 − j) << 4) ⊕ round in row 7.
    fn permute_add(&self, state: &mut [u64; MAX_COLUMNS]) {
        let columns = self.columns;
        for round in 0..self.rounds {
            for (c, column) in state[..columns].iter_mut().enumerate() {
                let row_7 = ((((columns - 1 - c) << ROUND_CONSTANT_COLUMN_SHIFT) ^ round) as u64)
                    << ADDITIVE_CONSTANT_ROW_SHIFT;
                *column = column.wrapping_add(ADDITIVE_CONSTANT ^ row_7);
            }
            self.apply_round(state);
        }
    }

    /// SubBytes, ShiftBytes and MixColumns: output row r of column c comes from column c − shift(r).
    fn apply_round(&self, state: &mut [u64; MAX_COLUMNS]) {
        let source = *state;
        let column_mask = self.columns - 1;
        let last_row_shift = if self.columns == SHORT_STATE_COLUMNS {
            ROWS - 1
        } else {
            LONG_STATE_LAST_ROW_SHIFT
        };
        for (c, column) in state[..self.columns].iter_mut().enumerate() {
            let mut mixed = 0u64;
            for (r, table) in ROUND_TABLES.iter().enumerate() {
                let shift = if r == ROWS - 1 { last_row_shift } else { r };
                let source_column = source[c.wrapping_sub(shift) & column_mask];
                mixed ^= table[((source_column >> (BYTE_BITS * r)) & BYTE_MASK) as usize];
            }
            *column = mixed;
        }
    }
}

impl fmt::Debug for Kupyna {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Kupyna")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut word = [0u8; COLUMN_BYTES];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}
