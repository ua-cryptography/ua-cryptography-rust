use ua_dstu_sboxes::PI;

pub(crate) const ROWS: usize = 8;
const BYTE_VALUE_COUNT: usize = 256;
const SBOX_COUNT: usize = 4;
const BYTE_BITS: usize = 8;
// The first row of the circulant MDS matrix of MixColumns.
const MDS_ROW: [u8; ROWS] = [0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04];
// x^8 + x^4 + x^3 + x^2 + 1, the field polynomial of MixColumns.
const FIELD_POLYNOMIAL: u16 = 0x11D;
const FIELD_OVERFLOW_BIT: u16 = 0x100;

/// SubBytes and MixColumns merged: `ROUND_TABLES[k][b]` is the column MixColumns makes from a column whose only
/// non-zero byte is π_(k mod 4)(b) in row k (the technique of the reference implementation and of BouncyCastle).
pub(crate) static ROUND_TABLES: [[u64; BYTE_VALUE_COUNT]; ROWS] = build_round_tables();

const fn build_round_tables() -> [[u64; BYTE_VALUE_COUNT]; ROWS] {
    let mut tables = [[0u64; BYTE_VALUE_COUNT]; ROWS];
    let mut k = 0;
    while k < ROWS {
        let mut b = 0;
        while b < BYTE_VALUE_COUNT {
            let substituted = PI[k % SBOX_COUNT][b];
            let mut column = 0u64;
            let mut i = 0;
            // Row i of the product: M[i][k] · y with M[i][k] = MDS_ROW[(k − i) mod 8].
            while i < ROWS {
                let coefficient = MDS_ROW[k.wrapping_sub(i) & (ROWS - 1)];
                column |= (multiply_in_field(coefficient, substituted) as u64) << (BYTE_BITS * i);
                i += 1;
            }
            tables[k][b] = column;
            b += 1;
        }
        k += 1;
    }
    tables
}

/// Multiplication in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1.
const fn multiply_in_field(a: u8, b: u8) -> u8 {
    let mut product: u16 = 0;
    let mut multiplicand = a as u16;
    let mut multiplier = b;
    while multiplier != 0 {
        if multiplier & 1 != 0 {
            product ^= multiplicand;
        }
        multiplicand <<= 1;
        if multiplicand & FIELD_OVERFLOW_BIT != 0 {
            multiplicand ^= FIELD_POLYNOMIAL;
        }
        multiplier >>= 1;
    }
    product as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_multiplication_reduces_by_the_kupyna_polynomial() {
        assert_eq!(multiply_in_field(0x80, 0x02), 0x1D);
        assert_eq!(multiply_in_field(0x01, 0xAB), 0xAB);
        assert_eq!(multiply_in_field(0x57, 0x13), multiply_in_field(0x13, 0x57));
    }

    #[test]
    fn the_table_of_row_0_holds_the_mds_row_times_the_substituted_byte() {
        let substituted = PI[0][0x00];
        let column = ROUND_TABLES[0][0x00];
        for i in 0..ROWS {
            let expected = multiply_in_field(MDS_ROW[(ROWS - i) % ROWS], substituted);
            assert_eq!((column >> (8 * i)) as u8, expected);
        }
    }
}
