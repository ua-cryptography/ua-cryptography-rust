//! Binary polynomials (elements of GF(2)[x]) in little-endian arrays of 64-bit words: the coefficient of x^i is
//! bit `i % 64` of word `i / 64`. The only CPU-dependent part is carry-less multiplication.

use crate::hardware_carryless;

/// Words of the largest supported field element (m ≤ 511 in either basis).
pub(crate) const MAX_WORDS: usize = 8;

/// Words of a product of two field elements before reduction.
pub(crate) const MAX_PRODUCT_WORDS: usize = 2 * MAX_WORDS;

/// The internal representation of a field element; words above the field's word count are zero.
pub(crate) type Words = [u64; MAX_WORDS];

/// Bits in one word.
pub(crate) const WORD_BITS: usize = 64;

const WORD_SHIFT: usize = 6;
const WORD_MASK: usize = WORD_BITS - 1;
const HALF_WORD_BITS: u32 = 32;
const LOW_HALF_MASK: u64 = 0xFFFF_FFFF;
const WINDOW_BITS: u32 = 4;
const WINDOW_ENTRIES: usize = 1 << WINDOW_BITS;
const WINDOW_MASK: u64 = (WINDOW_ENTRIES - 1) as u64;
const TOP_WINDOW_SHIFT: u32 = 60;

/// r = a · b in GF(2)[x]; r must hold `a.len() + b.len()` words.
pub(crate) fn multiply(a: &[u64], b: &[u64], r: &mut [u64]) {
    let r = &mut r[..a.len() + b.len()];
    match hardware_unit() {
        Some(unit) => unit.multiply(a, b, r),
        None => multiply_portable(a, b, r),
    }
}

/// Portable path of [`multiply`]: a 4-bit window table per word of b.
pub(crate) fn multiply_portable(a: &[u64], b: &[u64], r: &mut [u64]) {
    r[..a.len() + b.len()].fill(0);
    let mut table = [0u64; WINDOW_ENTRIES];
    for (j, &b_word) in b.iter().enumerate() {
        fill_window_table(b_word, &mut table);
        for (i, &a_word) in a.iter().enumerate() {
            let (low, high) = multiply_word(a_word, b_word, &table);
            r[i + j] ^= low;
            r[i + j + 1] ^= high;
        }
    }
}

/// r = a² in GF(2)[x] (bit i moves to bit 2i); r must hold `2 · a.len()` words.
pub(crate) fn square(a: &[u64], r: &mut [u64]) {
    for (i, &word) in a.iter().enumerate() {
        r[2 * i] = spread_low_half(word & LOW_HALF_MASK);
        r[2 * i + 1] = spread_low_half(word >> HALF_WORD_BITS);
    }
}

/// dst = src >> shift; bits below zero and bits that do not fit into dst are dropped.
pub(crate) fn shift_right(src: &[u64], shift: usize, dst: &mut [u64]) {
    let words = shift >> WORD_SHIFT;
    let bits = shift & WORD_MASK;
    for (i, target) in dst.iter_mut().enumerate() {
        let k = i + words;
        let mut low = word_at(src, k);
        if bits != 0 {
            let high = word_at(src, k + 1);
            low = (low >> bits) | (high << (WORD_BITS - bits));
        }
        *target = low;
    }
}

/// dst = src << shift, truncated to `dst.len()` words.
pub(crate) fn shift_left(src: &[u64], shift: usize, dst: &mut [u64]) {
    let words = shift >> WORD_SHIFT;
    let bits = shift & WORD_MASK;
    for (i, target) in dst.iter_mut().enumerate() {
        let mut high = if i >= words { word_at(src, i - words) } else { 0 };
        if bits != 0 {
            let low = if i > words { word_at(src, i - words - 1) } else { 0 };
            high = (high << bits) | (low >> (WORD_BITS - bits));
        }
        *target = high;
    }
}

/// Reverses the order of the lowest `64 · src.len()` bits: dst bit (64n − 1 − u) = src bit u.
pub(crate) fn reverse_words(src: &[u64], dst: &mut [u64]) {
    for (target, &word) in dst.iter_mut().zip(src.iter().rev()) {
        *target = word.reverse_bits();
    }
}

/// Clears every bit at a position ≥ `bit_count`.
pub(crate) fn clear_above(a: &mut [u64], bit_count: usize) {
    let mut word = bit_count >> WORD_SHIFT;
    let bits = bit_count & WORD_MASK;
    if word >= a.len() {
        return;
    }
    if bits != 0 {
        a[word] &= (1u64 << bits) - 1;
        word += 1;
    }
    a[word..].fill(0);
}

/// a ^= b over the length of a.
pub(crate) fn xor_into(a: &mut [u64], b: &[u64]) {
    for (target, &word) in a.iter_mut().zip(b) {
        *target ^= word;
    }
}

pub(crate) fn is_zero(a: &[u64]) -> bool {
    a.iter().fold(0, |acc, &word| acc | word) == 0
}

pub(crate) fn test_bit(a: &[u64], bit: usize) -> bool {
    (a[bit >> WORD_SHIFT] >> (bit & WORD_MASK)) & 1 != 0
}

pub(crate) fn flip_bit(a: &mut [u64], bit: usize) {
    a[bit >> WORD_SHIFT] ^= 1u64 << (bit & WORD_MASK);
}

/// Parity (sum mod 2) of all bits.
pub(crate) fn parity(a: &[u64]) -> u8 {
    (a.iter().fold(0, |acc, &word| acc ^ word).count_ones() & 1) as u8
}

/// Whether the hardware carry-less multiplication is in use.
pub(crate) fn uses_hardware() -> bool {
    hardware_unit().is_some()
}

fn hardware_unit() -> Option<hardware_carryless::CarrylessUnit> {
    if cfg!(feature = "portable") || tests_force_portable() {
        return None;
    }
    hardware_carryless::detect()
}

#[cfg(not(test))]
fn tests_force_portable() -> bool {
    false
}

#[cfg(test)]
thread_local! {
    static FORCE_PORTABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn tests_force_portable() -> bool {
    FORCE_PORTABLE.with(std::cell::Cell::get)
}

/// Runs `action` with the portable multiplication forced on the current thread.
#[cfg(test)]
pub(crate) fn with_portable_multiplication<T>(action: impl FnOnce() -> T) -> T {
    FORCE_PORTABLE.with(|force| force.set(true));
    let result = action();
    FORCE_PORTABLE.with(|force| force.set(false));
    result
}

/// A word of the polynomial; the words past its end are zero.
fn word_at(words: &[u64], index: usize) -> u64 {
    if index < words.len() { words[index] } else { 0 }
}

/// table[k] = k · b mod x^64 for k = 0..15.
fn fill_window_table(b: u64, table: &mut [u64; WINDOW_ENTRIES]) {
    table[0] = 0;
    table[1] = b;
    for k in (2..WINDOW_ENTRIES).step_by(2) {
        table[k] = table[k >> 1] << 1;
        table[k + 1] = table[k] ^ b;
    }
}

/// Portable 64 × 64 → 128-bit carry-less product (low, high) by a 4-bit window.
fn multiply_word(a: u64, b: u64, table: &[u64; WINDOW_ENTRIES]) -> (u64, u64) {
    let mut low = table[(a >> TOP_WINDOW_SHIFT) as usize];
    let mut high = 0u64;
    for shift in (0..TOP_WINDOW_SHIFT).step_by(WINDOW_BITS as usize).rev() {
        high = (high << WINDOW_BITS) | (low >> TOP_WINDOW_SHIFT);
        low = (low << WINDOW_BITS) ^ table[((a >> shift) & WINDOW_MASK) as usize];
    }

    // The table entries lost the top bits of b shifted out by the window (k · b overflows 64 bits).
    high ^= ((a & 0xEEEE_EEEE_EEEE_EEEE) >> 1) & 0u64.wrapping_sub(b >> 63);
    high ^= ((a & 0xCCCC_CCCC_CCCC_CCCC) >> 2) & 0u64.wrapping_sub((b >> 62) & 1);
    high ^= ((a & 0x8888_8888_8888_8888) >> 3) & 0u64.wrapping_sub((b >> 61) & 1);
    (low, high)
}

/// Inserts a zero bit after every bit of the low 32 bits of x.
fn spread_low_half(x: u64) -> u64 {
    let mut x = x;
    x = (x | (x << 16)) & 0x0000_FFFF_0000_FFFF;
    x = (x | (x << 8)) & 0x00FF_00FF_00FF_00FF;
    x = (x | (x << 4)) & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x | (x << 2)) & 0x3333_3333_3333_3333;
    x = (x | (x << 1)) & 0x5555_5555_5555_5555;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SplitMix64: a deterministic generator of test words.
    struct TestWords(u64);

    impl TestWords {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn words(&mut self, count: usize) -> Vec<u64> {
            (0..count).map(|_| self.next()).collect()
        }
    }

    /// Schoolbook bit-by-bit product, the slowest and most obvious reference.
    fn naive_multiply(a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut r = vec![0u64; a.len() + b.len()];
        for i in 0..a.len() * WORD_BITS {
            if !test_bit(a, i) {
                continue;
            }
            for j in 0..b.len() * WORD_BITS {
                if test_bit(b, j) {
                    flip_bit(&mut r, i + j);
                }
            }
        }
        r
    }

    #[test]
    fn portable_multiplication_matches_the_schoolbook_product() {
        for (a_words, b_words) in [(1, 1), (1, 3), (3, 3), (4, 7), (8, 8), (16, 16)] {
            let mut random = TestWords((a_words * 100 + b_words) as u64);
            for iteration in 0..20 {
                let (mut a, mut b) = (random.words(a_words), random.words(b_words));
                if iteration == 0 {
                    // All top bits set: exercises the repair of the bits the window loses.
                    a.fill(u64::MAX);
                    b.fill(u64::MAX);
                }
                let mut r = vec![0u64; a_words + b_words];
                multiply_portable(&a, &b, &mut r);
                assert_eq!(naive_multiply(&a, &b), r, "{a_words} × {b_words} words");
            }
        }
    }

    #[test]
    fn hardware_multiplication_matches_the_portable_one() {
        let Some(unit) = hardware_carryless::detect() else {
            return; // nothing to compare on this CPU
        };
        let mut random = TestWords(7);
        for iteration in 0..200 {
            let words = 1 + iteration % 9;
            let (a, b) = (random.words(words), random.words(words));
            let mut hardware = vec![0u64; 2 * words];
            let mut portable = vec![0u64; 2 * words];
            unit.multiply(&a, &b, &mut hardware);
            multiply_portable(&a, &b, &mut portable);
            assert_eq!(portable, hardware);
        }
    }

    #[test]
    fn hardware_multiplication_handles_operands_of_different_lengths() {
        let Some(unit) = hardware_carryless::detect() else {
            return;
        };
        let mut random = TestWords(8);
        for (a_words, b_words) in [(1, 5), (5, 1), (3, 8), (8, 2)] {
            let (a, b) = (random.words(a_words), random.words(b_words));
            let mut hardware = vec![0u64; a_words + b_words];
            unit.multiply(&a, &b, &mut hardware);
            assert_eq!(naive_multiply(&a, &b), hardware);
        }
    }

    #[test]
    fn squaring_matches_multiplication() {
        let mut random = TestWords(3);
        for iteration in 0..50 {
            let a = random.words(1 + iteration % 8);
            let mut squared = vec![0u64; 2 * a.len()];
            square(&a, &mut squared);
            assert_eq!(naive_multiply(&a, &a), squared);
        }
    }

    #[test]
    fn bit_reversal_mirrors_every_bit() {
        let mut random = TestWords(5);
        for _ in 0..200 {
            let x = random.next();
            let expected = (0..64).fold(0u64, |acc, i| acc | (((x >> i) & 1) << (63 - i)));
            let mut reversed = [0u64; 1];
            reverse_words(&[x], &mut reversed);
            assert_eq!(expected, reversed[0]);
        }
    }

    #[test]
    fn shifts_left_and_right_are_inverse() {
        for shift in [0, 1, 63, 64, 65, 130] {
            let mut random = TestWords(shift as u64);
            let a = random.words(4);
            let mut left = [0u64; 8];
            shift_left(&a, shift, &mut left);
            let mut back = [0u64; 4];
            shift_right(&left, shift, &mut back);
            assert_eq!(a, back, "shift {shift}");

            let mut wide = [0u64; 8];
            shift_right(&left, shift, &mut wide);
            assert_eq!(a, wide[..4], "shift {shift}");
            assert!(wide[4..].iter().all(|&word| word == 0), "shift {shift}");
        }
    }

    #[test]
    fn forcing_the_portable_path_turns_the_hardware_off_on_this_thread() {
        assert!(with_portable_multiplication(|| !uses_hardware()));
    }
}
