//! Data conversions of DSTU 4145-2002, section 5.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use ua_gf2m::{BinaryField, FieldElement};
use ua_gost::Gost34311;

use crate::SignatureEncodingError;

const BYTE_BITS: u32 = 8;
/// L_D is a multiple of 16 (5.7).
const SIGNATURE_BITS_GRANULE: u32 = 16;

/// 5.8: field element → integer, the L(n) − 1 least significant bits of the standard representation (< n).
pub fn field_element_to_integer(x: &FieldElement, n: &BigUint) -> BigUint {
    let k = bit_length(n) - 1;
    x.to_biguint() & ((BigUint::one() << k) - 1u32)
}

/// 5.9: hash code → field element: its min(m, L_H) least significant bits.
///
/// The hash is the binary string (h_{L_H−1}, …, h_0), most significant byte first, as the hex strings of Appendix Б;
/// GOST 34.311 outputs the opposite order, so reverse its digest first.
pub fn hash_to_field_element(hash: &[u8], field: &BinaryField) -> FieldElement {
    let m = field.m();
    let h = BigUint::from_bytes_be(hash) & ((BigUint::one() << m) - 1u32);
    match FieldElement::from_biguint(field, &h) {
        Ok(element) => element,
        Err(error) => unreachable!("a value cut to m bits is an element: {error}"),
    }
}

/// 6.2, 5.6: H(T) by GOST 34.311 with the default DKE as the binary string (h_255, …, h_0), most significant byte
/// first: the digest reversed.
pub fn hash_message(message: &[u8]) -> Vec<u8> {
    hash_message_with_hasher(message, &mut Gost34311::default())
}

/// H(T) by the GOST 34.311 of `hasher` (e.g. one built from a certificate's DKE), most significant byte first.
pub fn hash_message_with_hasher(message: &[u8], hasher: &mut Gost34311) -> Vec<u8> {
    let mut digest = hasher.hash(message).to_vec();
    digest.reverse();
    digest
}

/// 5.10: (r, s) → the signature D = S‖R of `signature_bits` bits as big-endian bytes (s in the upper half).
pub fn encode_signature(r: &BigUint, s: &BigUint, signature_bits: u32) -> Result<Vec<u8>, SignatureEncodingError> {
    if signature_bits == 0 || signature_bits % SIGNATURE_BITS_GRANULE != 0 {
        return Err(SignatureEncodingError::LengthNotMultipleOf16(signature_bits));
    }
    let half = signature_bits / 2;
    let fits = |value: &BigUint| !value.is_zero() && bit_length(value) <= u64::from(half);
    if !fits(r) || !fits(s) {
        return Err(SignatureEncodingError::ValueOutOfRange);
    }

    let d = (s << half) | r;
    let digits = d.to_bytes_be();
    let mut signature = vec![0u8; (signature_bits / BYTE_BITS) as usize - digits.len()];
    signature.extend_from_slice(&digits);
    Ok(signature)
}

/// 5.11: the signature D (big-endian bytes) → (r, s), each half of its bits.
pub fn decode_signature(signature: &[u8]) -> Result<(BigUint, BigUint), SignatureEncodingError> {
    if signature.is_empty() {
        return Err(SignatureEncodingError::Empty);
    }
    let half = signature.len() as u64 * u64::from(BYTE_BITS) / 2;
    let d = BigUint::from_bytes_be(signature);
    let mask = (BigUint::one() << half) - 1u32;
    Ok((&d & &mask, d >> half))
}

/// L(a) of 5.1: the length of the binary representation; L(0) = 1.
pub fn bit_length(a: &BigUint) -> u64 {
    if a.is_zero() { 1 } else { a.bits() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_length_of_zero_is_one() {
        assert_eq!(1, bit_length(&BigUint::zero()));
        assert_eq!(1, bit_length(&BigUint::one()));
        assert_eq!(9, bit_length(&BigUint::from(256u32)));
    }

    #[test]
    fn an_empty_signature_is_refused() {
        assert_eq!(Err(SignatureEncodingError::Empty), decode_signature(&[]));
    }
}
