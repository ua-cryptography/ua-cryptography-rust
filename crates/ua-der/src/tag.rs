//! Identifier octets of the universal ASN.1 types used by PKI structures (X.680, 8.4), and context tags.

/// BOOLEAN.
pub const BOOLEAN: u8 = 0x01;
/// INTEGER.
pub const INTEGER: u8 = 0x02;
/// BIT STRING.
pub const BIT_STRING: u8 = 0x03;
/// OCTET STRING.
pub const OCTET_STRING: u8 = 0x04;
/// NULL.
pub const NULL: u8 = 0x05;
/// OBJECT IDENTIFIER.
pub const OBJECT_IDENTIFIER: u8 = 0x06;
/// ENUMERATED.
pub const ENUMERATED: u8 = 0x0A;
/// UTF8String.
pub const UTF8_STRING: u8 = 0x0C;
/// NumericString.
pub const NUMERIC_STRING: u8 = 0x12;
/// PrintableString.
pub const PRINTABLE_STRING: u8 = 0x13;
/// TeletexString (T61String).
pub const TELETEX_STRING: u8 = 0x14;
/// IA5String.
pub const IA5_STRING: u8 = 0x16;
/// UTCTime.
pub const UTC_TIME: u8 = 0x17;
/// GeneralizedTime.
pub const GENERALIZED_TIME: u8 = 0x18;
/// VisibleString.
pub const VISIBLE_STRING: u8 = 0x1A;
/// UniversalString.
pub const UNIVERSAL_STRING: u8 = 0x1C;
/// BMPString.
pub const BMP_STRING: u8 = 0x1E;
/// SEQUENCE and SEQUENCE OF (constructed).
pub const SEQUENCE: u8 = 0x30;
/// SET and SET OF (constructed).
pub const SET: u8 = 0x31;

/// Bits 8–7 of the identifier octet: the class.
pub(crate) const CLASS_MASK: u8 = 0xC0;
/// The context-specific class.
pub(crate) const CONTEXT_CLASS: u8 = 0x80;
/// Bit 6 of the identifier octet: the constructed form.
pub(crate) const CONSTRUCTED: u8 = 0x20;
/// Bits 5–1 of the identifier octet: the tag number (31 announces the high-tag-number form).
pub(crate) const NUMBER_MASK: u8 = 0x1F;
/// The largest tag number of the low-tag-number form.
pub(crate) const MAX_LOW_NUMBER: u8 = 30;

/// Context-specific constructed tag [`number`] (EXPLICIT tagging, or IMPLICIT over a constructed type).
///
/// # Panics
/// If `number` is above 30: high tag numbers are not supported.
pub const fn context_constructed(number: u8) -> u8 {
    assert!(
        number <= MAX_LOW_NUMBER,
        "context tag numbers above 30 are not supported"
    );
    CONTEXT_CLASS | CONSTRUCTED | number
}

/// Context-specific primitive tag [`number`] (IMPLICIT over a primitive type).
///
/// # Panics
/// If `number` is above 30: high tag numbers are not supported.
pub const fn context_primitive(number: u8) -> u8 {
    assert!(
        number <= MAX_LOW_NUMBER,
        "context tag numbers above 30 are not supported"
    );
    CONTEXT_CLASS | number
}
