//! Hex text tolerant to the formatting of the standard's tables.

use num_bigint::BigUint;

use crate::HexError;

const HEX_RADIX: u32 = 16;
const HEX_PREFIX_LENGTH: usize = 2;
/// The line-continuation mark of the standard's tables.
const LINE_CONTINUATION: char = '/';

/// Parses a big-endian hex number; whitespace, line breaks, '/' and a leading "0x" are ignored.
pub fn parse_hex(text: &str) -> Result<BigUint, HexError> {
    let trimmed = text.trim();
    let unprefixed = if has_hex_prefix(trimmed) {
        &trimmed[HEX_PREFIX_LENGTH..]
    } else {
        trimmed
    };
    let mut digits = Vec::with_capacity(unprefixed.len());
    for character in unprefixed.chars() {
        if character.is_whitespace() || character == LINE_CONTINUATION {
            continue;
        }
        if !character.is_ascii_hexdigit() {
            return Err(HexError::InvalidCharacter(character));
        }
        digits.push(character as u8);
    }
    if digits.is_empty() {
        return Err(HexError::Empty);
    }
    BigUint::parse_bytes(&digits, HEX_RADIX).ok_or(HexError::Empty)
}

/// Formats a number as upper-case hex without leading zeros ("0" for zero).
pub fn format_hex(value: &BigUint) -> String {
    format!("{value:X}")
}

/// Formats a number as upper-case hex left-padded with zeros to `digits` characters.
pub fn format_hex_padded(value: &BigUint, digits: usize) -> String {
    format!("{value:0>digits$X}")
}

/// Parses hex text into bytes, two digits per byte; whitespace is ignored.
pub fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, HexError> {
    let mut nibbles = Vec::with_capacity(text.len());
    for character in text.chars().filter(|character| !character.is_whitespace()) {
        let nibble = character
            .to_digit(HEX_RADIX)
            .ok_or(HexError::InvalidCharacter(character))?;
        nibbles.push(nibble as u8);
    }
    if nibbles.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    Ok(nibbles.chunks_exact(2).map(|pair| (pair[0] << 4) | pair[1]).collect())
}

fn has_hex_prefix(text: &str) -> bool {
    text.len() >= HEX_PREFIX_LENGTH && text[..HEX_PREFIX_LENGTH].eq_ignore_ascii_case("0x")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_ignores_the_formatting_of_the_standard() {
        let value = parse_hex(" 0x5FF6 1084/\n62A2 ").unwrap();
        assert_eq!(BigUint::from(0x5FF6_1084_62A2u64), value);
    }

    #[test]
    fn parsing_refuses_foreign_characters_and_empty_text() {
        assert_eq!(Err(HexError::InvalidCharacter('G')), parse_hex("12G4"));
        assert_eq!(Err(HexError::Empty), parse_hex(" / "));
        assert_eq!(Err(HexError::Empty), parse_hex("0x"));
    }

    #[test]
    fn formatting_is_upper_case_and_pads_on_request() {
        let value = BigUint::from(0xABCu32);
        assert_eq!("ABC", format_hex(&value));
        assert_eq!("00ABC", format_hex_padded(&value, 5));
        assert_eq!("0", format_hex(&BigUint::default()));
    }

    #[test]
    fn byte_strings_need_an_even_number_of_digits() {
        assert_eq!(vec![0x01, 0xAB], parse_hex_bytes("01 ab").unwrap());
        assert_eq!(Err(HexError::OddLength), parse_hex_bytes("123"));
        assert_eq!(Ok(Vec::new()), parse_hex_bytes(""));
    }
}
