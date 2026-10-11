use num_bigint::BigInt;
use num_bigint::BigUint;
use time::OffsetDateTime;

use crate::character_string::decode_character_string;
use crate::errors::DerError;
use crate::oid::decode_oid;
use crate::tag;
use crate::time_text::parse_generalized_time;
use crate::time_text::parse_utc_time;

/// The deepest nesting the reader follows; deeper input is refused, not recursed into.
const MAX_DEPTH: usize = 64;
/// The first length octet of the indefinite form (X.690, 8.1.3.6).
const INDEFINITE_LENGTH: u8 = 0x80;
/// Set on the first length octet of the long form; the low bits count the length octets.
const LONG_LENGTH_FLAG: u8 = 0x80;
/// The low bits of the first length octet of the long form.
const LENGTH_OCTET_COUNT_MASK: u8 = 0x7F;
/// The most length octets the reader accepts.
const MAX_LENGTH_OCTETS: usize = 4;
/// The longest contents the reader accepts (2^31 - 1).
const MAX_CONTENT_LENGTH: u64 = i32::MAX as u64;
/// The two octets that close an indefinite-length element (X.690, 8.1.5).
const END_OF_CONTENTS: [u8; 2] = [0x00, 0x00];
/// The identifier octet and the first length octet.
const MIN_HEADER_LENGTH: usize = 2;
/// The bits of one octet.
const BITS_PER_OCTET: usize = 8;
/// The octet of a BIT STRING that counts its unused bits.
const UNUSED_BITS_OCTETS: usize = 1;
/// The most unused bits a BIT STRING may claim.
const MAX_UNUSED_BITS: u8 = 7;
/// The octets of a named BIT STRING that fit the 32-bit result.
const MAX_NAMED_BIT_OCTETS: usize = 4;
/// The most significant bit of an octet: ASN.1 bit 0 of that octet.
const FIRST_BIT_OF_OCTET: u8 = 0x80;

/// One parsed ASN.1 element (tag, length, contents) over the original bytes.
///
/// The reader accepts DER and the BER forms met in CMS (indefinite lengths, constructed strings); [`encoded`] is
/// always the exact slice of the input, so signed structures (TBSCertificate, signed attributes, tbsResponseData)
/// are hashed as they were received. Only low tag numbers (0–30) are supported: PKI structures use no others.
/// Children are parsed when asked for, and the nesting depth is limited to 64.
///
/// [`encoded`]: Asn1Node::encoded
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Node<'a> {
    tag: u8,
    encoded: &'a [u8],
    content: &'a [u8],
    depth: usize,
}

impl<'a> Asn1Node<'a> {
    /// Parses exactly one element; trailing bytes are refused.
    pub fn parse(data: &'a [u8]) -> Result<Self, DerError> {
        let node = read_element(data, 0, 0)?;
        let count = data.len() - node.encoded.len();
        if count != 0 {
            return Err(DerError::TrailingBytes { count });
        }
        Ok(node)
    }

    /// Parses the first element of `data`; its length is `encoded().len()`, and what follows is left alone.
    pub fn parse_first(data: &'a [u8]) -> Result<Self, DerError> {
        read_element(data, 0, 0)
    }

    /// The identifier octet: class (bits 8–7), constructed flag (bit 6) and tag number.
    pub fn tag(&self) -> u8 {
        self.tag
    }

    /// The whole element: identifier, length and contents (for an indefinite length, up to the end-of-contents).
    pub fn encoded(&self) -> &'a [u8] {
        self.encoded
    }

    /// The contents octets (for an indefinite length, without the end-of-contents octets).
    pub fn content(&self) -> &'a [u8] {
        self.content
    }

    /// True for the constructed form.
    pub fn is_constructed(&self) -> bool {
        self.tag & tag::CONSTRUCTED != 0
    }

    /// True for a context-specific tag [`number`], primitive or constructed.
    pub fn is_context(&self, number: u8) -> bool {
        self.tag & tag::CLASS_MASK == tag::CONTEXT_CLASS && self.tag & tag::NUMBER_MASK == number
    }

    /// True when the identifier octet is `expected`.
    pub fn has_tag(&self, expected: u8) -> bool {
        self.tag == expected
    }

    /// The element itself when its identifier octet is `expected`; refuses any other.
    pub fn expect_tag(self, expected: u8) -> Result<Self, DerError> {
        if self.tag == expected {
            Ok(self)
        } else {
            Err(DerError::UnexpectedTag {
                expected,
                found: self.tag,
            })
        }
    }

    /// The children of a constructed element; refuses a primitive one or malformed contents.
    pub fn children(&self) -> Result<Vec<Asn1Node<'a>>, DerError> {
        if !self.is_constructed() {
            return Err(DerError::Primitive { tag: self.tag });
        }
        read_elements(self.content, self.depth + 1)
    }

    /// The child at `index`; refuses when there is no such child.
    pub fn child(&self, index: usize) -> Result<Asn1Node<'a>, DerError> {
        let children = self.children()?;
        children.get(index).copied().ok_or(DerError::MissingChild {
            tag: self.tag,
            count: children.len(),
            index,
        })
    }

    /// The value of an INTEGER.
    pub fn to_integer(&self) -> Result<BigInt, DerError> {
        self.expect_tag(tag::INTEGER)?;
        if self.content.is_empty() {
            return Err(DerError::EmptyInteger);
        }
        Ok(BigInt::from_signed_bytes_be(self.content))
    }

    /// The value of an INTEGER that must not be negative (a serial number, a field size).
    pub fn to_unsigned_integer(&self) -> Result<BigUint, DerError> {
        self.to_integer()?.to_biguint().ok_or(DerError::NegativeInteger)
    }

    /// The value of an INTEGER that fits 32 bits.
    pub fn to_i32(&self) -> Result<i32, DerError> {
        i32::try_from(self.to_integer()?).map_err(|_| DerError::IntegerOutOfRange)
    }

    /// The value of a BOOLEAN: any non-zero octet is true.
    pub fn to_boolean(&self) -> Result<bool, DerError> {
        self.expect_tag(tag::BOOLEAN)?;
        match self.content {
            [octet] => Ok(*octet != 0),
            _ => Err(DerError::InvalidBoolean),
        }
    }

    /// The dotted-decimal text of an OBJECT IDENTIFIER.
    pub fn to_oid(&self) -> Result<String, DerError> {
        self.expect_tag(tag::OBJECT_IDENTIFIER)?;
        decode_oid(self.content)
    }

    /// The contents of an OCTET STRING, primitive or constructed (BER), under any tag (an implicit one too).
    pub fn to_octet_string(&self) -> Result<Vec<u8>, DerError> {
        if !self.is_constructed() {
            return Ok(self.content.to_vec());
        }
        let mut octets = Vec::new();
        for segment in self.children()? {
            octets.extend_from_slice(&segment.to_octet_string()?);
        }
        Ok(octets)
    }

    /// The octets of a BIT STRING after its unused-bits octet (keys and signatures have no unused bits).
    pub fn to_bit_string(&self) -> Result<&'a [u8], DerError> {
        self.expect_tag(tag::BIT_STRING)?;
        match self.content.split_first() {
            Some((&unused_bits, octets)) if unused_bits <= MAX_UNUSED_BITS => Ok(octets),
            _ => Err(DerError::InvalidBitString),
        }
    }

    /// A named BIT STRING (such as keyUsage) as bits: ASN.1 bit `i` is bit `i` of the result, up to bit 31.
    pub fn to_named_bits(&self) -> Result<u32, DerError> {
        self.expect_tag(tag::BIT_STRING)?;
        let octets = self.content.iter().skip(UNUSED_BITS_OCTETS).take(MAX_NAMED_BIT_OCTETS);
        let mut bits = 0u32;
        for (octet_index, octet) in octets.enumerate() {
            for bit in 0..BITS_PER_OCTET {
                if octet & (FIRST_BIT_OF_OCTET >> bit) != 0 {
                    bits |= 1 << (octet_index * BITS_PER_OCTET + bit);
                }
            }
        }
        Ok(bits)
    }

    /// Any ASN.1 character string type as text; undecodable sequences become U+FFFD.
    pub fn to_text(&self) -> Result<String, DerError> {
        decode_character_string(self.tag, self.content)
    }

    /// A UTCTime or GeneralizedTime value, in UTC.
    pub fn to_time(&self) -> Result<OffsetDateTime, DerError> {
        match self.tag {
            tag::UTC_TIME => parse_utc_time(self.content),
            tag::GENERALIZED_TIME => parse_generalized_time(self.content),
            found => Err(DerError::NotTime { tag: found }),
        }
    }
}

fn read_elements(data: &[u8], depth: usize) -> Result<Vec<Asn1Node<'_>>, DerError> {
    let mut elements = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let element = read_element(data, offset, depth)?;
        offset += element.encoded.len();
        elements.push(element);
    }
    Ok(elements)
}

fn read_element(data: &[u8], offset: usize, depth: usize) -> Result<Asn1Node<'_>, DerError> {
    if depth > MAX_DEPTH {
        return Err(DerError::TooDeep);
    }
    if data.len() - offset < MIN_HEADER_LENGTH {
        return Err(DerError::Truncated);
    }
    let identifier = data[offset];
    if identifier & tag::NUMBER_MASK == tag::NUMBER_MASK {
        return Err(DerError::HighTagNumber);
    }
    let first_length_octet = data[offset + 1];
    let content_start = offset + MIN_HEADER_LENGTH;
    if first_length_octet == INDEFINITE_LENGTH {
        return read_indefinite_element(data, offset, depth);
    }
    let (content_length, length_octets) = read_definite_length(data, content_start, first_length_octet)?;
    let content_start = content_start + length_octets;
    if content_length > data.len() - content_start {
        return Err(DerError::LengthExceedsData);
    }
    let content_end = content_start + content_length;
    Ok(Asn1Node {
        tag: identifier,
        encoded: &data[offset..content_end],
        content: &data[content_start..content_end],
        depth,
    })
}

// BER indefinite length: children up to the end-of-contents octets 00 00 (X.690, 8.1.3.6).
fn read_indefinite_element(data: &[u8], offset: usize, depth: usize) -> Result<Asn1Node<'_>, DerError> {
    let identifier = data[offset];
    if identifier & tag::CONSTRUCTED == 0 {
        return Err(DerError::IndefinitePrimitive);
    }
    let content_start = offset + MIN_HEADER_LENGTH;
    let mut position = content_start;
    loop {
        let rest = &data[position..];
        if rest.len() < END_OF_CONTENTS.len() {
            return Err(DerError::MissingEndOfContents);
        }
        if rest.starts_with(&END_OF_CONTENTS) {
            break;
        }
        position += read_element(data, position, depth + 1)?.encoded.len();
    }
    Ok(Asn1Node {
        tag: identifier,
        encoded: &data[offset..position + END_OF_CONTENTS.len()],
        content: &data[content_start..position],
        depth,
    })
}

// The short form, or the long form with up to four length octets; returns the length and the octets it took.
fn read_definite_length(data: &[u8], position: usize, first_octet: u8) -> Result<(usize, usize), DerError> {
    if first_octet & LONG_LENGTH_FLAG == 0 {
        return Ok((usize::from(first_octet), 0));
    }
    let octet_count = usize::from(first_octet & LENGTH_OCTET_COUNT_MASK);
    if octet_count > MAX_LENGTH_OCTETS || octet_count > data.len() - position {
        return Err(DerError::InvalidLength);
    }
    let length = data[position..position + octet_count]
        .iter()
        .fold(0u64, |length, &octet| (length << BITS_PER_OCTET) | u64::from(octet));
    if length > MAX_CONTENT_LENGTH {
        return Err(DerError::LengthTooLarge);
    }
    let length = usize::try_from(length).map_err(|_| DerError::LengthTooLarge)?;
    Ok((length, octet_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_long_form_may_use_more_octets_than_needed() {
        let node = Asn1Node::parse(&[0x04, 0x82, 0x00, 0x01, 0xAB]).unwrap();
        assert_eq!(node.content(), [0xAB]);
    }

    #[test]
    fn a_primitive_element_with_an_indefinite_length_is_refused() {
        assert_eq!(
            Asn1Node::parse(&[0x04, 0x80, 0x00, 0x00]),
            Err(DerError::IndefinitePrimitive)
        );
    }

    #[test]
    fn a_length_of_two_to_the_thirty_one_is_refused() {
        assert_eq!(
            Asn1Node::parse(&[0x04, 0x84, 0x80, 0x00, 0x00, 0x00]),
            Err(DerError::LengthTooLarge)
        );
    }

    #[test]
    fn named_bits_ignore_octets_past_the_fourth() {
        let node = Asn1Node::parse(&[0x03, 0x06, 0x00, 0x80, 0x00, 0x00, 0x01, 0xFF]).unwrap();
        assert_eq!(node.to_named_bits().unwrap(), 1 | 1 << 31);
    }
}
