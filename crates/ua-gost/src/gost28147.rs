use std::fmt;

use crate::DEFAULT_DKE;
use crate::SubstitutionTableError;

const BLOCK_BYTES: usize = 8;
const KEY_BYTES: usize = 32;
const SBOX_ENTRY_COUNT: usize = 128;
const DKE_BYTES: usize = 64;
const SUBKEY_COUNT: usize = 8;
const SBOX_ENTRY_LIMIT: u8 = 16;
const NIBBLE_MASK: u8 = 0x0F;
const NIBBLE_BITS: u32 = 4;
const ENTRIES_PER_SBOX: usize = 16;
const BYTE_VALUE_COUNT: usize = 256;
const ROUND_VALUE_BYTES: usize = 4;
const ROUND_ROTATION_BITS: u32 = 11;
const HALF_BLOCK_BYTES: usize = 4;
const BYTE_MASK: u32 = 0xFF;

// Encryption: subkeys K0..K7 three times, then K7..K0.
const ENCRYPTION_SUBKEY_ORDER: [usize; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, //
    0, 1, 2, 3, 4, 5, 6, 7, //
    0, 1, 2, 3, 4, 5, 6, 7, //
    7, 6, 5, 4, 3, 2, 1, 0, //
];

// Decryption: subkeys K0..K7 once, then K7..K0 three times.
const DECRYPTION_SUBKEY_ORDER: [usize; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, //
    7, 6, 5, 4, 3, 2, 1, 0, //
    7, 6, 5, 4, 3, 2, 1, 0, //
    7, 6, 5, 4, 3, 2, 1, 0, //
];

/// GOST 28147-89 block cipher in simple substitution (ECB) mode on single 64-bit blocks.
///
/// The substitution table is 8 S-boxes of 16 four-bit entries, 128 bytes: entry `v` of S-box `j` is
/// `sbox[16 j + v]`, and S-box `j` substitutes bits `4j..4j+3` of the round value. Ukrainian PKI carries the table
/// as a 64-byte DKE; see [`Gost28147::expand_dke`]. The key is all zeros until [`Gost28147::set_key`].
#[derive(Clone)]
pub struct Gost28147 {
    // The S-boxes merged by bytes and pre-rotated by 11 bits: f(x) is four lookups.
    round_table: [u32; ROUND_VALUE_BYTES * BYTE_VALUE_COUNT],
    subkeys: [u32; SUBKEY_COUNT],
}

impl Gost28147 {
    /// The block length in bytes.
    pub const BLOCK_BYTES: usize = BLOCK_BYTES;
    /// The key length in bytes.
    pub const KEY_BYTES: usize = KEY_BYTES;
    /// The number of entries of an expanded substitution table.
    pub const SBOX_ENTRY_COUNT: usize = SBOX_ENTRY_COUNT;
    /// The length of a DKE in bytes.
    pub const DKE_BYTES: usize = DKE_BYTES;

    /// Creates the cipher with a 128-entry substitution table; refuses another length or an entry above 15.
    pub fn new(sbox: &[u8]) -> Result<Self, SubstitutionTableError> {
        let sbox: &[u8; SBOX_ENTRY_COUNT] = sbox
            .try_into()
            .map_err(|_| SubstitutionTableError::WrongTableLength { length: sbox.len() })?;
        if let Some((index, &value)) = sbox.iter().enumerate().find(|(_, entry)| **entry >= SBOX_ENTRY_LIMIT) {
            return Err(SubstitutionTableError::EntryOutOfRange { index, value });
        }
        Ok(Self::from_checked_sbox(sbox))
    }

    /// Expands a 64-byte DKE (two S-box entries per byte, high nibble first) into the 128-entry table.
    pub fn expand_dke(dke: &[u8]) -> Result<[u8; SBOX_ENTRY_COUNT], SubstitutionTableError> {
        let dke: &[u8; DKE_BYTES] = dke
            .try_into()
            .map_err(|_| SubstitutionTableError::WrongDkeLength { length: dke.len() })?;
        Ok(expand_checked_dke(dke))
    }

    /// Sets the 256-bit key: eight 32-bit little-endian subkeys K0..K7.
    pub fn set_key(&mut self, key: &[u8; KEY_BYTES]) {
        for (subkey, bytes) in self.subkeys.iter_mut().zip(key.chunks_exact(HALF_BLOCK_BYTES)) {
            *subkey = read_u32_le(bytes);
        }
    }

    /// Encrypts one block (N1 = the first four bytes, N2 = the last four, little-endian).
    pub fn encrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        self.transform_block(block, &ENCRYPTION_SUBKEY_ORDER)
    }

    /// Decrypts one block.
    pub fn decrypt_block(&self, block: &[u8; BLOCK_BYTES]) -> [u8; BLOCK_BYTES] {
        self.transform_block(block, &DECRYPTION_SUBKEY_ORDER)
    }

    /// The cipher over a table already known to hold 128 four-bit entries.
    pub(crate) fn from_checked_sbox(sbox: &[u8; SBOX_ENTRY_COUNT]) -> Self {
        Self {
            round_table: build_round_table(sbox),
            subkeys: [0; SUBKEY_COUNT],
        }
    }

    /// 32 rounds; the last one does not swap N1 and N2.
    fn transform_block(&self, block: &[u8; BLOCK_BYTES], subkey_order: &[usize; 32]) -> [u8; BLOCK_BYTES] {
        let (left, right) = block.split_at(HALF_BLOCK_BYTES);
        let mut n1 = read_u32_le(left);
        let mut n2 = read_u32_le(right);
        let (swapping, last) = subkey_order.split_at(subkey_order.len() - 1);
        for &j in swapping {
            (n1, n2) = (n2 ^ self.round_function(n1.wrapping_add(self.subkeys[j])), n1);
        }
        n2 ^= self.round_function(n1.wrapping_add(self.subkeys[last[0]]));

        let mut output = [0u8; BLOCK_BYTES];
        output[..HALF_BLOCK_BYTES].copy_from_slice(&n1.to_le_bytes());
        output[HALF_BLOCK_BYTES..].copy_from_slice(&n2.to_le_bytes());
        output
    }

    /// f(x) = rotl11(S(x)).
    fn round_function(&self, x: u32) -> u32 {
        let mut result = 0;
        for byte_index in 0..ROUND_VALUE_BYTES {
            let byte = ((x >> (8 * byte_index)) & BYTE_MASK) as usize;
            result ^= self.round_table[BYTE_VALUE_COUNT * byte_index + byte];
        }
        result
    }
}

impl Default for Gost28147 {
    /// The cipher over [`DEFAULT_DKE`] with a zero key.
    fn default() -> Self {
        Self::from_checked_sbox(&expand_checked_dke(&DEFAULT_DKE))
    }
}

impl fmt::Debug for Gost28147 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Gost28147").finish_non_exhaustive()
    }
}

/// Expands a DKE of the right length; every nibble is a valid entry.
pub(crate) fn expand_checked_dke(dke: &[u8; DKE_BYTES]) -> [u8; SBOX_ENTRY_COUNT] {
    let mut sbox = [0u8; SBOX_ENTRY_COUNT];
    for (pair, &byte) in sbox.chunks_exact_mut(2).zip(dke) {
        pair[0] = byte >> NIBBLE_BITS;
        pair[1] = byte & NIBBLE_MASK;
    }
    sbox
}

// S works nibble-wise, so S followed by the rotation is a sum of four byte-indexed tables.
fn build_round_table(sbox: &[u8; SBOX_ENTRY_COUNT]) -> [u32; ROUND_VALUE_BYTES * BYTE_VALUE_COUNT] {
    let mut table = [0u32; ROUND_VALUE_BYTES * BYTE_VALUE_COUNT];
    for byte_index in 0..ROUND_VALUE_BYTES {
        let low_sbox = &sbox[ENTRIES_PER_SBOX * (2 * byte_index)..][..ENTRIES_PER_SBOX];
        let high_sbox = &sbox[ENTRIES_PER_SBOX * (2 * byte_index + 1)..][..ENTRIES_PER_SBOX];
        for value in 0..BYTE_VALUE_COUNT {
            let low = u32::from(low_sbox[value & usize::from(NIBBLE_MASK)]);
            let high = u32::from(high_sbox[value >> NIBBLE_BITS]);
            let substituted = (low | (high << NIBBLE_BITS)) << (8 * byte_index);
            table[BYTE_VALUE_COUNT * byte_index + value] = substituted.rotate_left(ROUND_ROTATION_BITS);
        }
    }
    table
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let mut word = [0u8; HALF_BLOCK_BYTES];
    word.copy_from_slice(bytes);
    u32::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dke_byte_expands_high_nibble_first() {
        let mut dke = [0u8; DKE_BYTES];
        dke[0] = 0xA9;
        dke[63] = 0x04;
        let sbox = expand_checked_dke(&dke);
        assert_eq!((sbox[0], sbox[1]), (0x0A, 0x09));
        assert_eq!((sbox[126], sbox[127]), (0x00, 0x04));
    }

    #[test]
    fn the_default_cipher_uses_dke_no_1() {
        let mut default = Gost28147::default();
        let mut explicit = Gost28147::new(&expand_checked_dke(&DEFAULT_DKE)).unwrap_or_else(|error| panic!("{error}"));
        default.set_key(&[7; KEY_BYTES]);
        explicit.set_key(&[7; KEY_BYTES]);
        assert_eq!(
            default.encrypt_block(&[1; BLOCK_BYTES]),
            explicit.encrypt_block(&[1; BLOCK_BYTES])
        );
    }

    #[test]
    fn a_table_of_wrong_length_or_with_a_wide_entry_is_refused() {
        assert_eq!(
            Gost28147::new(&[0; 64]).err(),
            Some(SubstitutionTableError::WrongTableLength { length: 64 })
        );
        let mut sbox = [0u8; SBOX_ENTRY_COUNT];
        sbox[5] = 16;
        assert_eq!(
            Gost28147::new(&sbox).err(),
            Some(SubstitutionTableError::EntryOutOfRange { index: 5, value: 16 })
        );
        assert_eq!(
            Gost28147::expand_dke(&[0; 63]).err(),
            Some(SubstitutionTableError::WrongDkeLength { length: 63 })
        );
    }
}
