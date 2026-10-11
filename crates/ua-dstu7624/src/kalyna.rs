use std::fmt;

use crate::BlockSize;
use crate::SetupError;
use crate::round_functions::apply_round;
use crate::round_functions::mix_columns;
use crate::round_functions::mix_columns_inverse;
use crate::round_functions::shift_rows;
use crate::round_functions::shift_rows_inverse;
use crate::round_functions::substitute_bytes;
use crate::round_functions::substitute_bytes_inverse;

const MAX_WORDS: usize = 8;
const MAX_ROUNDS: usize = 18;
const WORD_BYTES: usize = 8;
const BITS_PER_BYTE: usize = 8;
const TWO_WORDS: usize = 2;
const FOUR_WORDS: usize = 4;
// The constant tmv of the key schedule, shifted left by one before every second even round key.
const INITIAL_TMV: u64 = 0x0001_0001_0001_0001;

/// The DSTU 7624:2014 "Kalyna" block cipher: 128-, 256- or 512-bit blocks with a key of the block length or of twice
/// the block length (128/128, 128/256, 256/256, 256/512, 512/512).
///
/// The state is a column-major 8 × c byte matrix stored as c 64-bit little-endian columns, as in DSTU 7564. The round
/// keys serve both directions, so one instance encrypts and decrypts.
#[derive(Clone)]
pub struct Kalyna {
    block_size: BlockSize,
    rounds: usize,
    round_keys: [[u64; MAX_WORDS]; MAX_ROUNDS + 1],
}

impl Kalyna {
    /// Expands `key`; refuses a key that is not one or two blocks long, or longer than 512 bits (table 6.1).
    pub fn new(block_size: BlockSize, key: &[u8]) -> Result<Self, SetupError> {
        let block_bytes = block_size.bytes();
        let key_bits = key.len() * BITS_PER_BYTE;
        let is_supported_key =
            matches!(key_bits, 128 | 256 | 512) && (key.len() == block_bytes || key.len() == 2 * block_bytes);
        if !is_supported_key {
            return Err(SetupError::WrongKeyLength {
                key_bytes: key.len(),
                block_bytes,
            });
        }
        let rounds = match key_bits {
            128 => 10,
            256 => 14,
            _ => 18,
        };
        let mut cipher = Self {
            block_size,
            rounds,
            round_keys: [[0; MAX_WORDS]; MAX_ROUNDS + 1],
        };
        cipher.expand_key(key);
        Ok(cipher)
    }

    /// The block length.
    pub fn block_size(&self) -> BlockSize {
        self.block_size
    }

    /// The block length in bytes.
    pub fn block_bytes(&self) -> usize {
        self.block_size.bytes()
    }

    /// Encrypts one block in place.
    ///
    /// # Panics
    /// When `block` is not exactly one block long.
    pub fn encrypt_block(&self, block: &mut [u8]) {
        let mut state = self.read_state(block);
        let words = self.words();
        let state = &mut state[..words];
        add_round_key(state, &self.round_keys[0]);
        for round in 1..=self.rounds {
            substitute_bytes(state);
            shift_rows(state);
            mix_columns(state);
            if round < self.rounds {
                xor_round_key(state, &self.round_keys[round]);
            }
        }
        add_round_key(state, &self.round_keys[self.rounds]);
        write_state(state, block);
    }

    /// Decrypts one block in place.
    ///
    /// # Panics
    /// When `block` is not exactly one block long.
    pub fn decrypt_block(&self, block: &mut [u8]) {
        let mut state = self.read_state(block);
        let words = self.words();
        let state = &mut state[..words];
        subtract_round_key(state, &self.round_keys[self.rounds]);
        for round in (0..self.rounds).rev() {
            mix_columns_inverse(state);
            shift_rows_inverse(state);
            substitute_bytes_inverse(state);
            if round > 0 {
                xor_round_key(state, &self.round_keys[round]);
            }
        }
        subtract_round_key(state, &self.round_keys[0]);
        write_state(state, block);
    }

    fn words(&self) -> usize {
        self.block_size.words()
    }

    fn read_state(&self, block: &[u8]) -> [u64; MAX_WORDS] {
        assert_eq!(
            block.len(),
            self.block_bytes(),
            "a Kalyna block is {} bytes",
            self.block_bytes()
        );
        let mut state = [0u64; MAX_WORDS];
        for (word, bytes) in state.iter_mut().zip(block.chunks_exact(WORD_BYTES)) {
            *word = read_u64_le(bytes);
        }
        state
    }

    /// The key schedule of DSTU 7624:2014: K_t, then the even round keys, then the odd ones by rotation.
    fn expand_key(&mut self, key: &[u8]) {
        let words = self.words();
        let mut key_words = [0u64; 2 * MAX_WORDS];
        let key_word_count = key.len() / WORD_BYTES;
        for (word, bytes) in key_words.iter_mut().zip(key.chunks_exact(WORD_BYTES)) {
            *word = read_u64_le(bytes);
        }
        let key_words = &mut key_words[..key_word_count];
        let intermediate_key = calculate_intermediate_key(key_words, words);
        self.expand_even_round_keys(key_words, &intermediate_key[..words]);
        for round in (1..self.rounds).step_by(2) {
            self.round_keys[round] = rotate_round_key(&self.round_keys[round - 1], words);
        }
    }

    fn expand_even_round_keys(&mut self, key_words: &mut [u64], intermediate_key: &[u64]) {
        let words = self.words();
        let is_double_key = key_words.len() != words;
        let mut tmv = INITIAL_TMV;
        let mut round = 0;
        loop {
            self.round_keys[round] = calculate_even_round_key(&key_words[..words], intermediate_key, tmv);
            if round == self.rounds {
                break;
            }
            if is_double_key {
                round += 2;
                tmv <<= 1;
                self.round_keys[round] = calculate_even_round_key(&key_words[words..], intermediate_key, tmv);
                if round == self.rounds {
                    break;
                }
            }
            round += 2;
            tmv <<= 1;
            key_words.rotate_left(1);
        }
    }
}

impl fmt::Debug for Kalyna {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Kalyna")
            .field("block_size", &self.block_size)
            .finish_non_exhaustive()
    }
}

/// K_t: three rounds over the block-length constant, keyed by the halves (or copies) of the key.
fn calculate_intermediate_key(key_words: &[u64], words: usize) -> [u64; MAX_WORDS] {
    let (k0, k1) = if key_words.len() == words {
        (key_words, key_words)
    } else {
        key_words.split_at(words)
    };
    let mut state = [0u64; MAX_WORDS];
    state[0] = (words + key_words.len() + 1) as u64;
    let state_words = &mut state[..words];
    add_round_key(state_words, k0);
    apply_round(state_words);
    xor_round_key(state_words, k1);
    apply_round(state_words);
    add_round_key(state_words, k0);
    apply_round(state_words);
    state
}

fn calculate_even_round_key(key_part: &[u64], intermediate_key: &[u64], tmv: u64) -> [u64; MAX_WORDS] {
    let words = intermediate_key.len();
    let mut shifted_key = [0u64; MAX_WORDS];
    for (target, &word) in shifted_key.iter_mut().zip(intermediate_key) {
        *target = word.wrapping_add(tmv);
    }
    let shifted_key = &shifted_key[..words];
    let mut state = [0u64; MAX_WORDS];
    for ((target, &key_word), &shifted_word) in state.iter_mut().zip(key_part).zip(shifted_key) {
        *target = key_word.wrapping_add(shifted_word);
    }
    let state_words = &mut state[..words];
    apply_round(state_words);
    xor_round_key(state_words, shifted_key);
    apply_round(state_words);
    add_round_key(state_words, shifted_key);
    state
}

/// An odd round key: the previous even key rotated left by 2c + 3 bytes (c columns).
fn rotate_round_key(x: &[u64; MAX_WORDS], words: usize) -> [u64; MAX_WORDS] {
    let mut z = [0u64; MAX_WORDS];
    match words {
        TWO_WORDS => {
            z[0] = (x[0] >> 56) | (x[1] << 8);
            z[1] = (x[1] >> 56) | (x[0] << 8);
        }
        FOUR_WORDS => {
            z[0] = (x[1] >> 24) | (x[2] << 40);
            z[1] = (x[2] >> 24) | (x[3] << 40);
            z[2] = (x[3] >> 24) | (x[0] << 40);
            z[3] = (x[0] >> 24) | (x[1] << 40);
        }
        _ => {
            for (i, word) in z.iter_mut().enumerate() {
                *word = (x[(i + 2) % MAX_WORDS] >> 24) | (x[(i + 3) % MAX_WORDS] << 40);
            }
        }
    }
    z
}

fn add_round_key(state: &mut [u64], key: &[u64]) {
    for (word, &key_word) in state.iter_mut().zip(key) {
        *word = word.wrapping_add(key_word);
    }
}

fn subtract_round_key(state: &mut [u64], key: &[u64]) {
    for (word, &key_word) in state.iter_mut().zip(key) {
        *word = word.wrapping_sub(key_word);
    }
}

fn xor_round_key(state: &mut [u64], key: &[u64]) {
    for (word, &key_word) in state.iter_mut().zip(key) {
        *word ^= key_word;
    }
}

fn write_state(state: &[u64], block: &mut [u8]) {
    for (bytes, word) in block.chunks_exact_mut(WORD_BYTES).zip(state) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
}

fn read_u64_le(bytes: &[u8]) -> u64 {
    let mut word = [0u8; WORD_BYTES];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}
