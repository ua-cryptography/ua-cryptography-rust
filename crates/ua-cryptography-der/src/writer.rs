//! The DER writer (X.690, section 10): every function returns one complete element, and constructed values are built
//! by nesting calls.

use std::cmp::Ordering;

use num_bigint::BigInt;
use num_bigint::BigUint;
use time::OffsetDateTime;
use time::UtcOffset;

use crate::oid::encode_oid;
use crate::tag;
use crate::time_text::format_generalized_time;
use crate::time_text::format_utc_time;

/// The longest contents of the short length form.
const MAX_SHORT_LENGTH: usize = 0x7F;
/// Set on the first length octet of the long form.
const LONG_LENGTH_FLAG: u8 = 0x80;
/// The most length octets the writer emits.
const MAX_LENGTH_OCTETS: usize = 4;
/// The bits of one octet.
const BITS_PER_OCTET: usize = 8;
/// The contents octet of BOOLEAN TRUE in DER (X.690, 11.1).
const DER_TRUE: u8 = 0xFF;
/// The contents octet of BOOLEAN FALSE.
const DER_FALSE: u8 = 0x00;
/// The bit that makes an octet negative in two's complement.
const SIGN_BIT: u8 = 0x80;
/// The highest bit position of the 32-bit named-bits value.
const HIGHEST_NAMED_BIT: u32 = 31;
/// The most significant bit of an octet: ASN.1 bit 0 of that octet.
const FIRST_BIT_OF_OCTET: u8 = 0x80;
/// The last bit of an octet, numbered from its most significant bit.
const LAST_BIT_OF_OCTET: usize = 7;
/// The octet a shorter SET OF component is padded with for sorting (X.690, 11.6).
const SET_OF_PADDING: u8 = 0x00;
/// What a character outside ASCII becomes in PrintableString and IA5String.
const ASCII_REPLACEMENT: u8 = b'?';
/// The first year X.509 Time writes as GeneralizedTime (RFC 5280, 4.1.2.5).
const FIRST_GENERALIZED_TIME_YEAR: i32 = 2050;
/// The first year X.509 Time writes as UTCTime.
const FIRST_UTC_TIME_YEAR: i32 = 1950;

/// An element with the identifier octet `identifier` and contents `content`, in the shortest length form.
///
/// # Panics
/// If the contents are longer than 2^32 - 1 octets.
pub fn encode(identifier: u8, content: &[u8]) -> Vec<u8> {
    let length_octets = length_octets_of(content.len());
    let mut element = Vec::with_capacity(2 + length_octets.len() + content.len());
    element.push(identifier);
    if content.len() <= MAX_SHORT_LENGTH {
        element.push(content.len() as u8);
    } else {
        element.push(LONG_LENGTH_FLAG | length_octets.len() as u8);
        element.extend_from_slice(&length_octets);
    }
    element.extend_from_slice(content);
    element
}

/// A SEQUENCE of complete elements, in the order given.
pub fn sequence<T: AsRef<[u8]>>(items: impl IntoIterator<Item = T>) -> Vec<u8> {
    encode(tag::SEQUENCE, &concatenate(items))
}

/// A DER SET OF: the encodings are sorted as octet strings (X.690, 11.6).
pub fn set_of<T: AsRef<[u8]>>(items: impl IntoIterator<Item = T>) -> Vec<u8> {
    let mut sorted: Vec<T> = items.into_iter().collect();
    sorted.sort_by(|a, b| compare_encodings(a.as_ref(), b.as_ref()));
    encode(tag::SET, &concatenate(sorted))
}

/// A BOOLEAN.
pub fn boolean(value: bool) -> Vec<u8> {
    encode(tag::BOOLEAN, &[if value { DER_TRUE } else { DER_FALSE }])
}

/// NULL.
pub fn null() -> Vec<u8> {
    encode(tag::NULL, &[])
}

/// An INTEGER in the shortest two's complement form.
pub fn integer(value: &BigInt) -> Vec<u8> {
    encode(tag::INTEGER, &value.to_signed_bytes_be())
}

/// An INTEGER from a non-negative value, in the shortest two's complement form.
pub fn integer_from_unsigned(value: &BigUint) -> Vec<u8> {
    let magnitude = value.to_bytes_be();
    if magnitude[0] & SIGN_BIT == 0 {
        return encode(tag::INTEGER, &magnitude);
    }
    let mut content = Vec::with_capacity(magnitude.len() + 1);
    content.push(0);
    content.extend_from_slice(&magnitude);
    encode(tag::INTEGER, &content)
}

/// An INTEGER from a machine integer.
pub fn integer_from_i64(value: i64) -> Vec<u8> {
    integer(&BigInt::from(value))
}

/// An OCTET STRING.
pub fn octet_string(value: &[u8]) -> Vec<u8> {
    encode(tag::OCTET_STRING, value)
}

/// A BIT STRING whose length is a whole number of octets.
pub fn bit_string(value: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(value.len() + 1);
    content.push(0);
    content.extend_from_slice(value);
    encode(tag::BIT_STRING, &content)
}

/// A named BIT STRING (X.690, 11.2.2): bit `i` of `bits` is ASN.1 bit `i`; trailing zero bits are removed.
pub fn named_bits(bits: u32) -> Vec<u8> {
    if bits == 0 {
        return encode(tag::BIT_STRING, &[0]);
    }
    let highest = (HIGHEST_NAMED_BIT - bits.leading_zeros()) as usize;
    let mut content = vec![0u8; highest / BITS_PER_OCTET + 2];
    content[0] = (LAST_BIT_OF_OCTET - highest % BITS_PER_OCTET) as u8;
    for bit in 0..=highest {
        if bits & (1 << bit) != 0 {
            content[1 + bit / BITS_PER_OCTET] |= FIRST_BIT_OF_OCTET >> (bit % BITS_PER_OCTET);
        }
    }
    encode(tag::BIT_STRING, &content)
}

/// A UTF8String.
pub fn utf8_string(value: &str) -> Vec<u8> {
    encode(tag::UTF8_STRING, value.as_bytes())
}

/// A PrintableString; a character outside ASCII becomes `?`.
pub fn printable_string(value: &str) -> Vec<u8> {
    encode(tag::PRINTABLE_STRING, &to_ascii(value))
}

/// An IA5String; a character outside ASCII becomes `?`.
pub fn ia5_string(value: &str) -> Vec<u8> {
    encode(tag::IA5_STRING, &to_ascii(value))
}

/// A UTCTime `YYMMDDhhmmssZ` of `at` in UTC, whole seconds.
pub fn utc_time(at: OffsetDateTime) -> Vec<u8> {
    encode(tag::UTC_TIME, format_utc_time(at).as_bytes())
}

/// A GeneralizedTime `YYYYMMDDhhmmssZ` of `at` in UTC, whole seconds.
///
/// # Panics
/// If the year in UTC is outside 1–9999.
pub fn generalized_time(at: OffsetDateTime) -> Vec<u8> {
    encode(tag::GENERALIZED_TIME, format_generalized_time(at).as_bytes())
}

/// X.509 Time (RFC 5280, 4.1.2.5): UTCTime for 1950–2049, GeneralizedTime otherwise.
pub fn x509_time(at: OffsetDateTime) -> Vec<u8> {
    let year = at.to_offset(UtcOffset::UTC).year();
    if (FIRST_UTC_TIME_YEAR..FIRST_GENERALIZED_TIME_YEAR).contains(&year) {
        utc_time(at)
    } else {
        generalized_time(at)
    }
}

/// An OBJECT IDENTIFIER from dotted-decimal text, meant for the OID constants of the code.
///
/// # Panics
/// If `oid` is not an object identifier; text from outside goes through [`encode_oid`](crate::encode_oid) first.
pub fn object_identifier(oid: &str) -> Vec<u8> {
    match encode_oid(oid) {
        Ok(content) => encode(tag::OBJECT_IDENTIFIER, &content),
        Err(error) => panic!("'{oid}' is not an object identifier constant: {error}"),
    }
}

/// An AlgorithmIdentifier with absent parameters, as the Ukrainian PKI writes its own algorithms.
///
/// # Panics
/// If `oid` is not an object identifier.
pub fn algorithm_identifier(oid: &str) -> Vec<u8> {
    sequence([object_identifier(oid)])
}

/// `[number] EXPLICIT`: a constructed context tag around a complete element.
///
/// # Panics
/// If `number` is above 30.
pub fn explicit(number: u8, inner: &[u8]) -> Vec<u8> {
    encode(tag::context_constructed(number), inner)
}

/// `[number] IMPLICIT`: the identifier of `encoded` is replaced, its constructed flag is kept.
///
/// # Panics
/// If `number` is above 30 or `encoded` is empty.
pub fn implicit(number: u8, encoded: &[u8]) -> Vec<u8> {
    assert!(!encoded.is_empty(), "IMPLICIT tagging needs a complete element");
    let mut element = encoded.to_vec();
    element[0] = tag::context_primitive(number) | (encoded[0] & tag::CONSTRUCTED);
    element
}

fn concatenate<T: AsRef<[u8]>>(items: impl IntoIterator<Item = T>) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item.as_ref());
    }
    content
}

// The big-endian length without leading zero octets; empty for the short form.
fn length_octets_of(length: usize) -> Vec<u8> {
    if length <= MAX_SHORT_LENGTH {
        return Vec::new();
    }
    let octets = length.to_be_bytes();
    let significant_count = (usize::BITS - length.leading_zeros()).div_ceil(BITS_PER_OCTET as u32) as usize;
    assert!(
        significant_count <= MAX_LENGTH_OCTETS,
        "DER contents longer than 2^32 - 1 octets"
    );
    octets[octets.len() - significant_count..].to_vec()
}

// Shorter encodings are compared as if padded with zero octets at the end (X.690, 11.6).
fn compare_encodings(a: &[u8], b: &[u8]) -> Ordering {
    let longest = a.len().max(b.len());
    for index in 0..longest {
        let left = octet_or_padding(a, index);
        let right = octet_or_padding(b, index);
        if left != right {
            return left.cmp(&right);
        }
    }
    a.len().cmp(&b.len())
}

fn octet_or_padding(encoding: &[u8], index: usize) -> u8 {
    match encoding.get(index) {
        Some(&octet) => octet,
        None => SET_OF_PADDING,
    }
}

fn to_ascii(value: &str) -> Vec<u8> {
    value
        .chars()
        .map(|character| {
            if character.is_ascii() {
                character as u8
            } else {
                ASCII_REPLACEMENT
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_with_zero_octets_decides_before_length() {
        assert_eq!(compare_encodings(&[0x04, 0x01], &[0x04, 0x01, 0x00]), Ordering::Less);
        assert_eq!(compare_encodings(&[0x04, 0x02], &[0x04, 0x01, 0x05]), Ordering::Greater);
    }

    #[test]
    fn the_length_takes_as_few_octets_as_it_needs() {
        assert_eq!(length_octets_of(0x7F), Vec::<u8>::new());
        assert_eq!(length_octets_of(0x80), [0x80]);
        assert_eq!(length_octets_of(0x1_0000), [0x01, 0x00, 0x00]);
        assert_eq!(length_octets_of(0xFFFF_FFFF), [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn implicit_tagging_keeps_the_constructed_flag() {
        assert_eq!(implicit(0, &[0x31, 0x00]), [0xA0, 0x00]);
        assert_eq!(implicit(6, &[0x16, 0x01, 0x61]), [0x86, 0x01, 0x61]);
    }
}
