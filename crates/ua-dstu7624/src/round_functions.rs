//! The round transformations of Kalyna on a state of 64-bit little-endian columns (BouncyCastle's bit-sliced form).

use ua_dstu_sboxes::INVERSE_PI;
use ua_dstu_sboxes::PI;

const SBOX_COUNT: usize = 4;
const BYTES_PER_WORD: usize = 8;
const BYTE_BITS: usize = 8;
const BYTE_MASK: u64 = 0xFF;
const TWO_WORDS: usize = 2;
const FOUR_WORDS: usize = 4;
// GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1: the low byte of the polynomial.
const FIELD_REDUCTION: u64 = 0x1D;
const LOW_SEVEN_BITS: u64 = 0x7F7F_7F7F_7F7F_7F7F;
const LOW_SIX_BITS: u64 = 0x3F3F_3F3F_3F3F_3F3F;
const BIT_7: u64 = 0x8080_8080_8080_8080;
const BIT_6: u64 = 0x4040_4040_4040_4040;

// ShiftRows as masked swaps of column pairs: row r rotates right by r·c/8 columns.
const SHIFT_ROWS_2: [(usize, usize, u64); 1] = [(0, 1, 0xFFFF_FFFF_0000_0000)];
const SHIFT_ROWS_4: [(usize, usize, u64); 4] = [
    (0, 2, 0xFFFF_FFFF_0000_0000),
    (1, 3, 0x0000_FFFF_FFFF_0000),
    (0, 1, 0xFFFF_0000_FFFF_0000),
    (2, 3, 0xFFFF_0000_FFFF_0000),
];
const SHIFT_ROWS_8: [(usize, usize, u64); 12] = [
    (0, 4, 0xFFFF_FFFF_0000_0000),
    (1, 5, 0x00FF_FFFF_FF00_0000),
    (2, 6, 0x0000_FFFF_FFFF_0000),
    (3, 7, 0x0000_00FF_FFFF_FF00),
    (0, 2, 0xFFFF_0000_FFFF_0000),
    (1, 3, 0x00FF_FF00_00FF_FF00),
    (4, 6, 0xFFFF_0000_FFFF_0000),
    (5, 7, 0x00FF_FF00_00FF_FF00),
    (0, 1, 0xFF00_FF00_FF00_FF00),
    (2, 3, 0xFF00_FF00_FF00_FF00),
    (4, 5, 0xFF00_FF00_FF00_FF00),
    (6, 7, 0xFF00_FF00_FF00_FF00),
];

/// SubBytes, ShiftRows and MixColumns: one encryption round without the key.
pub(crate) fn apply_round(state: &mut [u64]) {
    substitute_bytes(state);
    shift_rows(state);
    mix_columns(state);
}

/// SubBytes: row r (byte r of every column) goes through π_(r mod 4).
pub(crate) fn substitute_bytes(state: &mut [u64]) {
    substitute(state, &PI);
}

/// The inverse of SubBytes.
pub(crate) fn substitute_bytes_inverse(state: &mut [u64]) {
    substitute(state, &INVERSE_PI);
}

/// ShiftRows.
pub(crate) fn shift_rows(state: &mut [u64]) {
    for &(first, second, mask) in shift_rows_swaps(state.len()) {
        swap_masked_bits(state, first, second, mask);
    }
}

/// The inverse of ShiftRows: the same swaps, each an involution, in reverse order.
pub(crate) fn shift_rows_inverse(state: &mut [u64]) {
    for &(first, second, mask) in shift_rows_swaps(state.len()).iter().rev() {
        swap_masked_bits(state, first, second, mask);
    }
}

/// MixColumns.
pub(crate) fn mix_columns(state: &mut [u64]) {
    for column in state.iter_mut() {
        *column = mix_column(*column);
    }
}

/// The inverse of MixColumns.
pub(crate) fn mix_columns_inverse(state: &mut [u64]) {
    for column in state.iter_mut() {
        *column = mix_column_inverse(*column);
    }
}

fn substitute(state: &mut [u64], sboxes: &[[u8; 256]; SBOX_COUNT]) {
    for column in state.iter_mut() {
        let mut substituted = 0u64;
        for row in 0..BYTES_PER_WORD {
            let byte = ((*column >> (BYTE_BITS * row)) & BYTE_MASK) as usize;
            substituted |= u64::from(sboxes[row % SBOX_COUNT][byte]) << (BYTE_BITS * row);
        }
        *column = substituted;
    }
}

fn shift_rows_swaps(words: usize) -> &'static [(usize, usize, u64)] {
    match words {
        TWO_WORDS => &SHIFT_ROWS_2,
        FOUR_WORDS => &SHIFT_ROWS_4,
        _ => &SHIFT_ROWS_8,
    }
}

/// Exchanges the bits selected by `mask` between two columns.
fn swap_masked_bits(state: &mut [u64], first: usize, second: usize, mask: u64) {
    let difference = (state[first] ^ state[second]) & mask;
    state[first] ^= difference;
    state[second] ^= difference;
}

/// A column times the circulant MDS matrix (01, 01, 05, 01, 08, 06, 07, 04) over GF(2^8).
fn mix_column(c: u64) -> u64 {
    let x1 = multiply_by_x(c);
    let mut u = c.rotate_right(8) ^ c;
    u ^= u.rotate_right(16);
    u ^= c.rotate_right(48);
    let v = multiply_by_x2(u ^ c ^ x1);
    u ^ v.rotate_right(32) ^ x1.rotate_right(40) ^ x1.rotate_right(48)
}

/// A column times the inverse matrix (AD, 95, 76, A8, 2F, 49, D7, CA).
fn mix_column_inverse(c: u64) -> u64 {
    let mut u0 = c;
    u0 ^= u0.rotate_right(8);
    u0 ^= u0.rotate_right(32);
    u0 ^= c.rotate_right(48);

    let t = u0 ^ c;
    let c48 = c.rotate_right(48);
    let c56 = c.rotate_right(56);

    let u7 = t ^ c56;
    let mut u6 = t.rotate_right(56);
    u6 ^= multiply_by_x(u7);
    let mut u5 = t.rotate_right(16) ^ c;
    u5 ^= (multiply_by_x(u6) ^ c).rotate_right(40);
    let mut u4 = t ^ c48;
    u4 ^= multiply_by_x(u5);
    let mut u3 = u0.rotate_right(16);
    u3 ^= multiply_by_x(u4);
    let mut u2 = t ^ c.rotate_right(24) ^ c48 ^ c56;
    u2 ^= multiply_by_x(u3);
    let mut u1 = t.rotate_right(32) ^ c ^ c56;
    u1 ^= multiply_by_x(u2);
    u0 ^= multiply_by_x(u1.rotate_right(40));
    u0
}

/// Every byte times x in GF(2^8).
fn multiply_by_x(n: u64) -> u64 {
    ((n & LOW_SEVEN_BITS) << 1) ^ (((n & BIT_7) >> 7).wrapping_mul(FIELD_REDUCTION))
}

/// Every byte times x^2 in GF(2^8).
fn multiply_by_x2(n: u64) -> u64 {
    ((n & LOW_SIX_BITS) << 2)
        ^ (((n & BIT_7) >> 6).wrapping_mul(FIELD_REDUCTION))
        ^ (((n & BIT_6) >> 6).wrapping_mul(FIELD_REDUCTION))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_inverse_undoes_its_transformation() {
        for words in [2, 4, 8] {
            let original: Vec<u64> = (0..words as u64)
                .map(|i| 0x0123_4567_89AB_CDEFu64.rotate_left(i as u32 * 7))
                .collect();
            let mut state = original.clone();
            substitute_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            mix_columns_inverse(&mut state);
            shift_rows_inverse(&mut state);
            substitute_bytes_inverse(&mut state);
            assert_eq!(state, original, "{words} columns");
        }
    }

    #[test]
    fn mix_column_of_a_unit_column_is_the_first_matrix_column() {
        // The column (1, 0, …, 0) maps to the first column of the circulant matrix: 01 04 07 06 08 01 05 01.
        assert_eq!(mix_column(1), 0x0105_0108_0607_0401);
    }
}
