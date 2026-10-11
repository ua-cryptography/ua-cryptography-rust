use crate::PI;

const SBOX_COUNT: usize = 4;
const SBOX_ENTRY_COUNT: usize = 256;

/// The inverses of π0..π3 (Kalyna decryption): `INVERSE_PI[k][PI[k][x]] == x`.
pub const INVERSE_PI: [[u8; SBOX_ENTRY_COUNT]; SBOX_COUNT] = invert_all(&PI);

const fn invert_all(sboxes: &[[u8; SBOX_ENTRY_COUNT]; SBOX_COUNT]) -> [[u8; SBOX_ENTRY_COUNT]; SBOX_COUNT] {
    let mut inverses = [[0u8; SBOX_ENTRY_COUNT]; SBOX_COUNT];
    let mut k = 0;
    while k < SBOX_COUNT {
        let mut x = 0;
        while x < SBOX_ENTRY_COUNT {
            inverses[k][sboxes[k][x] as usize] = x as u8;
            x += 1;
        }
        k += 1;
    }
    inverses
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sbox_is_a_permutation_and_its_inverse_undoes_it() {
        for k in 0..SBOX_COUNT {
            let mut seen = [false; SBOX_ENTRY_COUNT];
            for x in 0..SBOX_ENTRY_COUNT {
                seen[usize::from(PI[k][x])] = true;
                assert_eq!(usize::from(INVERSE_PI[k][usize::from(PI[k][x])]), x);
            }
            assert!(seen.iter().all(|&hit| hit), "π{k} is not a permutation");
        }
    }
}
