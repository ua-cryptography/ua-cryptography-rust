//! GF(2^n) for the GCM and XTS modes of DSTU 7624: bit i of the little-endian words is the coefficient of x^i.

use crate::BlockSize;

const WORD_BITS: u32 = 64;
const TOP_BIT_SHIFT: u32 = 63;

/// The low part of the field polynomial: x^7 + x^2 + x + 1, x^10 + x^5 + x^2 + 1, x^8 + x^5 + x^2 + 1.
pub(crate) fn reduction_of(block_size: BlockSize) -> u64 {
    match block_size {
        BlockSize::Bits128 => 0x87,
        BlockSize::Bits256 => 0x425,
        BlockSize::Bits512 => 0x125,
    }
}

/// t ← t·x.
pub(crate) fn multiply_by_x(t: &mut [u64], reduction: u64) {
    let mut carry = 0u64;
    for word in t.iter_mut() {
        let top_bit = *word >> TOP_BIT_SHIFT;
        *word = (*word << 1) ^ carry;
        carry = top_bit;
    }
    t[0] ^= reduction & 0u64.wrapping_sub(carry);
}

/// a·b, by Horner's rule from the top bit of `b`.
pub(crate) fn multiply(a: &[u64], b: &[u64], reduction: u64) -> Vec<u64> {
    let mut product = vec![0u64; a.len()];
    for &word in b.iter().rev() {
        for bit in (0..WORD_BITS).rev() {
            multiply_by_x(&mut product, reduction);
            let mask = 0u64.wrapping_sub((word >> bit) & 1);
            for (target, &a_word) in product.iter_mut().zip(a) {
                *target ^= a_word & mask;
            }
        }
    }
    product
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_to_the_n_reduces_to_the_low_part_of_the_polynomial() {
        let reduction = reduction_of(BlockSize::Bits128);
        let mut top = vec![0u64, 1 << 63];
        multiply_by_x(&mut top, reduction);
        assert_eq!(top, vec![reduction, 0]);
    }

    #[test]
    fn multiplication_by_one_and_by_x_agree_with_the_definitions() {
        let reduction = reduction_of(BlockSize::Bits256);
        let a = vec![
            0xDEAD_BEEF_0123_4567,
            0x89AB_CDEF_FEDC_BA98,
            0x0F0F_0F0F_F0F0_F0F0,
            0x8000_0000_0000_0001,
        ];
        assert_eq!(multiply(&a, &[1, 0, 0, 0], reduction), a);
        let mut doubled = a.clone();
        multiply_by_x(&mut doubled, reduction);
        assert_eq!(multiply(&a, &[2, 0, 0, 0], reduction), doubled);
        assert_eq!(multiply(&a, &doubled, reduction), multiply(&doubled, &a, reduction));
    }
}
