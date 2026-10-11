//! The ASN.1 character string types as text.

use std::char::REPLACEMENT_CHARACTER;

use crate::errors::DerError;
use crate::tag;

/// The octets of one BMPString (UCS-2 / UTF-16) code unit.
const UTF16_UNIT_LENGTH: usize = 2;
/// The octets of one UniversalString (UCS-4) character.
const UTF32_UNIT_LENGTH: usize = 4;

/// The text of a character string element; undecodable sequences become U+FFFD, as a lenient decoder does.
pub(crate) fn decode_character_string(identifier: u8, content: &[u8]) -> Result<String, DerError> {
    match identifier {
        tag::UTF8_STRING => Ok(String::from_utf8_lossy(content).into_owned()),
        tag::BMP_STRING => Ok(decode_utf16_big_endian(content)),
        tag::UNIVERSAL_STRING => Ok(decode_utf32_big_endian(content)),
        tag::PRINTABLE_STRING | tag::IA5_STRING | tag::NUMERIC_STRING | tag::VISIBLE_STRING | tag::TELETEX_STRING => {
            Ok(decode_latin1(content))
        }
        found => Err(DerError::NotCharacterString { tag: found }),
    }
}

// An unpaired surrogate, or an odd trailing octet, is one U+FFFD.
fn decode_utf16_big_endian(content: &[u8]) -> String {
    let chunks = content.chunks_exact(UTF16_UNIT_LENGTH);
    let has_partial_unit = !chunks.remainder().is_empty();
    let units = chunks.map(|pair| u16::from_be_bytes([pair[0], pair[1]]));
    let mut text: String = char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(REPLACEMENT_CHARACTER))
        .collect();
    if has_partial_unit {
        text.push(REPLACEMENT_CHARACTER);
    }
    text
}

// A value that is not a Unicode scalar, or 1–3 trailing octets, is one U+FFFD.
fn decode_utf32_big_endian(content: &[u8]) -> String {
    let chunks = content.chunks_exact(UTF32_UNIT_LENGTH);
    let has_partial_unit = !chunks.remainder().is_empty();
    let mut text: String = chunks
        .map(|quad| char::from_u32(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]])))
        .map(|scalar| scalar.unwrap_or(REPLACEMENT_CHARACTER))
        .collect();
    if has_partial_unit {
        text.push(REPLACEMENT_CHARACTER);
    }
    text
}

fn decode_latin1(content: &[u8]) -> String {
    content.iter().map(|&octet| char::from(octet)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_utf16_becomes_replacement_characters() {
        let text = decode_character_string(tag::BMP_STRING, &[0xD8, 0x00, 0x00, 0x41, 0x00]).unwrap();
        assert_eq!(text, "\u{FFFD}A\u{FFFD}");
    }

    #[test]
    fn broken_utf32_becomes_replacement_characters() {
        let content = [0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00];
        assert_eq!(
            decode_character_string(tag::UNIVERSAL_STRING, &content).unwrap(),
            "\u{FFFD}A\u{FFFD}"
        );
    }

    #[test]
    fn broken_utf8_becomes_replacement_characters() {
        let text = decode_character_string(tag::UTF8_STRING, &[0xC3, 0x28, 0xE2, 0x82]).unwrap();
        assert_eq!(text, "\u{FFFD}(\u{FFFD}");
    }

    #[test]
    fn teletex_octets_are_latin1() {
        assert_eq!(
            decode_character_string(tag::TELETEX_STRING, &[0x41, 0xE9]).unwrap(),
            "Aé"
        );
    }

    #[test]
    fn an_octet_string_is_not_text() {
        assert_eq!(
            decode_character_string(tag::OCTET_STRING, b"a"),
            Err(DerError::NotCharacterString { tag: tag::OCTET_STRING })
        );
    }
}
