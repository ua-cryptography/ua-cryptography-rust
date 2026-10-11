//! Object identifiers (X.690, 8.19): dotted-decimal text to contents octets and back.

use num_bigint::BigUint;

use crate::errors::DerError;
use crate::errors::OidError;

/// The arcs one value of the first subidentifier spans: `first * 40 + second` (X.690, 8.19.4).
const ARCS_PER_ROOT: u32 = 40;
/// The first subidentifier from which the first arc is 2 (joint-iso-itu-t).
const ROOT_TWO_START: u32 = MAX_ROOT_ARC * ARCS_PER_ROOT;
/// The largest first arc.
const MAX_ROOT_ARC: u32 = 2;
/// The seven value bits of a subidentifier octet.
const SUBIDENTIFIER_BITS: u8 = 0x7F;
/// Set on every octet of a subidentifier but its last.
const CONTINUATION_BIT: u8 = 0x80;
/// The bits each subidentifier octet carries.
const BITS_PER_OCTET: usize = 7;
/// The radix of the subidentifier groups.
const SUBIDENTIFIER_RADIX: u32 = 128;
/// Decimal digits of the arcs.
const DECIMAL_RADIX: u32 = 10;

/// The contents octets of an OBJECT IDENTIFIER written as dotted-decimal text (`"1.2.804.2.1.1.1"`); refuses text
/// that is not one.
pub fn encode_oid(oid: &str) -> Result<Vec<u8>, OidError> {
    let arcs = parse_arcs(oid)?;
    let root = BigUint::from(MAX_ROOT_ARC);
    let arcs_per_root = BigUint::from(ARCS_PER_ROOT);
    if arcs[0] > root || (arcs[0] < root && arcs[1] >= arcs_per_root) {
        return Err(OidError::RootArcsOutOfRange);
    }
    let mut contents = Vec::new();
    write_base128(&mut contents, &(&arcs[0] * &arcs_per_root + &arcs[1]));
    for arc in &arcs[2..] {
        write_base128(&mut contents, arc);
    }
    Ok(contents)
}

/// The dotted-decimal text of OBJECT IDENTIFIER contents octets; refuses empty contents or an unfinished last
/// subidentifier.
pub fn decode_oid(contents: &[u8]) -> Result<String, DerError> {
    match contents.last() {
        Some(last) if last & CONTINUATION_BIT == 0 => {}
        _ => return Err(DerError::InvalidObjectIdentifier),
    }
    let mut arcs: Vec<BigUint> = Vec::new();
    let mut value = BigUint::ZERO;
    for &octet in contents {
        value = (value << BITS_PER_OCTET) | BigUint::from(octet & SUBIDENTIFIER_BITS);
        if octet & CONTINUATION_BIT != 0 {
            continue;
        }
        if arcs.is_empty() {
            let root = root_arc_of(&value);
            let second = value - BigUint::from(root * ARCS_PER_ROOT);
            arcs.push(BigUint::from(root));
            arcs.push(second);
        } else {
            arcs.push(value);
        }
        value = BigUint::ZERO;
    }
    let texts: Vec<String> = arcs.iter().map(BigUint::to_string).collect();
    Ok(texts.join("."))
}

fn parse_arcs(oid: &str) -> Result<Vec<BigUint>, OidError> {
    let parts: Vec<&str> = oid.split('.').collect();
    if parts.len() < 2 {
        return Err(OidError::TooFewArcs);
    }
    parts.iter().map(|part| parse_arc(part)).collect()
}

fn parse_arc(part: &str) -> Result<BigUint, OidError> {
    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OidError::NotANumber);
    }
    BigUint::parse_bytes(part.as_bytes(), DECIMAL_RADIX).ok_or(OidError::NotANumber)
}

// X.690, 8.19.4: the first subidentifier holds the first two arcs.
fn root_arc_of(first_subidentifier: &BigUint) -> u32 {
    let arcs_per_root = BigUint::from(ARCS_PER_ROOT);
    if *first_subidentifier < arcs_per_root {
        0
    } else if *first_subidentifier < BigUint::from(ROOT_TWO_START) {
        1
    } else {
        MAX_ROOT_ARC
    }
}

// Base 128, most significant group first, the continuation bit on all groups but the last (X.690, 8.19.2).
fn write_base128(output: &mut Vec<u8>, value: &BigUint) {
    let groups = value.to_radix_be(SUBIDENTIFIER_RADIX);
    let last = groups.len() - 1;
    for (index, group) in groups.into_iter().enumerate() {
        let continuation = if index == last { 0 } else { CONTINUATION_BIT };
        output.push(continuation | group);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_arc_above_two_to_the_sixty_four_round_trips() {
        let text = "1.3.6.1.4.1.18446744073709551616.5";
        assert_eq!(decode_oid(&encode_oid(text).unwrap()).unwrap(), text);
    }

    #[test]
    fn the_first_subidentifier_splits_into_the_root_arcs() {
        assert_eq!(encode_oid("0.0").unwrap(), [0x00]);
        assert_eq!(decode_oid(&[0x00]).unwrap(), "0.0");
        assert_eq!(decode_oid(&[0x27]).unwrap(), "0.39");
        assert_eq!(decode_oid(&[0x28]).unwrap(), "1.0");
        assert_eq!(decode_oid(&[0x50]).unwrap(), "2.0");
        assert_eq!(decode_oid(&[0x88, 0x37, 0x01]).unwrap(), "2.999.1");
    }

    #[test]
    fn malformed_text_is_refused() {
        assert_eq!(encode_oid("1"), Err(OidError::TooFewArcs));
        assert_eq!(encode_oid("1..2"), Err(OidError::NotANumber));
        assert_eq!(encode_oid("1.+2"), Err(OidError::NotANumber));
        assert_eq!(encode_oid("1.2.x"), Err(OidError::NotANumber));
        assert_eq!(encode_oid("3.1"), Err(OidError::RootArcsOutOfRange));
        assert_eq!(encode_oid("1.40"), Err(OidError::RootArcsOutOfRange));
        assert!(encode_oid("2.40").is_ok());
    }

    #[test]
    fn unfinished_contents_are_refused() {
        assert_eq!(decode_oid(&[]), Err(DerError::InvalidObjectIdentifier));
        assert_eq!(decode_oid(&[0x2A, 0x86]), Err(DerError::InvalidObjectIdentifier));
    }
}
