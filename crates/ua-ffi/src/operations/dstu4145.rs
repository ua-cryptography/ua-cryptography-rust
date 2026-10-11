//! DSTU 4145-2002 on the recommended curves of Appendix Г. Integers are big-endian bytes: d and e of any length
//! below n, the signature D = S‖R as 5.10 writes it; Q is compressed (6.9), ⌈m / 8⌉ bytes. A hash code H(T) is
//! taken most significant byte first (5.9): the national PKI reverses GOST 34.311 and DSTU 7564 digests, and
//! stores D reversed (little-endian).

use num_bigint::BigUint;
use rand_core::RngCore;
use ua_dstu4145::{
    DomainParameters, RandomGenerator, Signer, get_optimal_normal_curve, get_polynomial_curve,
    hash_message_with_hasher, hash_to_field_element,
};
use ua_gf2m::CurvePoint;
use ua_gost::Gost28147;

use crate::errors::OperationFailure;
use crate::models::simple_types::CurveBasis;
use crate::models::{EncodedKeyPair, NamedCurve, SignatureHalves};
use crate::operations::gost34311;

/// The bits of a byte.
const BYTE_BITS: u64 = 8;

/// The domain parameters of the recommended curve.
pub fn get_domain(curve: NamedCurve) -> Result<DomainParameters, OperationFailure> {
    match curve.basis {
        CurveBasis::Polynomial => Ok(get_polynomial_curve(curve.m)?),
        CurveBasis::OptimalNormal => Ok(get_optimal_normal_curve(curve.m)?),
    }
}

/// Section 9: a random d (from the OS generator) and Q = −dP; d is padded to ⌈L(n) / 8⌉ bytes.
pub fn generate_key_pair(curve: NamedCurve) -> Result<EncodedKeyPair, OperationFailure> {
    let domain = get_domain(curve)?;
    let key_pair = Signer::new(&domain).generate_key_pair();
    Ok(EncodedKeyPair {
        private_key: to_fixed_bytes(&key_pair.private_key, domain.n()),
        public_key: domain.curve().compress_to_bytes(&key_pair.public_key)?,
    })
}

/// 9.2: the compressed Q = −dP of the private key d.
pub fn calculate_public_key(curve: NamedCurve, private_key: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    let domain = get_domain(curve)?;
    let q = Signer::new(&domain).calculate_public_key(&BigUint::from_bytes_be(private_key))?;
    Ok(domain.curve().compress_to_bytes(&q)?)
}

/// 6.10 and 10.1: the compressed key decompresses to a point of order n; refuses with the failed clause.
pub fn validate_public_key(curve: NamedCurve, public_key: &[u8]) -> Result<(), OperationFailure> {
    let domain = get_domain(curve)?;
    let q = domain.curve().decompress_from_bytes(public_key)?;
    Ok(domain.validate_public_key(&q)?)
}

/// Section 12: signs a hash code with a random presignature; `signature_bits` is L_D (the shortest when absent).
pub fn sign_hash(
    curve: NamedCurve,
    private_key: &[u8],
    hash: &[u8],
    signature_bits: Option<u32>,
) -> Result<Vec<u8>, OperationFailure> {
    let domain = get_domain(curve)?;
    let mut signer = Signer::new(&domain);
    let d = BigUint::from_bytes_be(private_key);
    match signature_bits {
        Some(signature_bits) => Ok(signer.sign_hash_with_length(&d, hash, signature_bits)?),
        None => Ok(signer.sign_hash(&d, hash)?),
    }
}

/// Section 12 with the given secret e of the presignature (section 11): the same e gives the same signature.
pub fn sign_hash_with_presignature(
    curve: NamedCurve,
    private_key: &[u8],
    hash: &[u8],
    e: &[u8],
    signature_bits: Option<u32>,
) -> Result<Vec<u8>, OperationFailure> {
    let domain = get_domain(curve)?;
    let signature_bits = read_signature_bits(&domain, signature_bits)?;
    if hash.is_empty() {
        return Err(OperationFailure::invalid_argument("The hash code has no bytes."));
    }
    let e = BigUint::from_bytes_be(e);
    if e == BigUint::ZERO || &e >= domain.n() {
        return Err(OperationFailure::invalid_argument("Section 11: e is not in 0 < e < n."));
    }
    let signer = Signer::new(&domain);
    let presignature = signer
        .calculate_presignature(&e)
        .ok_or_else(|| OperationFailure::invalid_argument("Section 11: x(eP) = 0; take another e."))?;
    let h = hash_to_field_element(hash, domain.field());
    let (r, s) = signer
        .sign(&BigUint::from_bytes_be(private_key), &h, &presignature)?
        .ok_or_else(|| OperationFailure::invalid_argument("Section 12: r = 0 or s = 0; take another e."))?;
    Ok(ua_dstu4145::encode_signature(&r, &s, signature_bits)?)
}

/// Section 13: whether D is a signature of the hash code under the compressed public key.
pub fn verify_hash(
    curve: NamedCurve,
    public_key: &[u8],
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, OperationFailure> {
    let domain = get_domain(curve)?;
    let q = decompress_public_key(&domain, public_key)?;
    Ok(Signer::new(&domain).verify_hash(&q, hash, signature))
}

/// Section 12 over H(T) by GOST 34.311 (6.2) with `dke`, DKE No. 1 when absent.
pub fn sign_message(
    curve: NamedCurve,
    private_key: &[u8],
    message: &[u8],
    dke: Option<&[u8]>,
    signature_bits: Option<u32>,
) -> Result<Vec<u8>, OperationFailure> {
    let hash = hash_message(message, dke)?;
    sign_hash(curve, private_key, &hash, signature_bits)
}

/// Section 13 over H(T) by GOST 34.311 (6.2) with `dke`, DKE No. 1 when absent.
pub fn verify_message(
    curve: NamedCurve,
    public_key: &[u8],
    message: &[u8],
    dke: Option<&[u8]>,
    signature: &[u8],
) -> Result<bool, OperationFailure> {
    let hash = hash_message(message, dke)?;
    verify_hash(curve, public_key, &hash, signature)
}

/// 5.10: (r, s) → D = S‖R of `signature_bits` bits.
pub fn encode_signature(r: &[u8], s: &[u8], signature_bits: u32) -> Result<Vec<u8>, OperationFailure> {
    let r = BigUint::from_bytes_be(r);
    let s = BigUint::from_bytes_be(s);
    Ok(ua_dstu4145::encode_signature(&r, &s, signature_bits)?)
}

/// 5.11: D → (r, s), each half of its bits.
pub fn decode_signature(signature: &[u8]) -> Result<SignatureHalves, OperationFailure> {
    let (r, s) = ua_dstu4145::decode_signature(signature)?;
    Ok(SignatureHalves {
        r: r.to_bytes_be(),
        s: s.to_bytes_be(),
    })
}

/// Appendix А: `count` bytes of the generator with the 256-bit key, the 64-bit seed, the date and time D in .NET
/// ticks (now when absent) and the 64-byte DKE (DKE No. 1 when absent).
pub fn generate_random_bytes(
    key: &[u8],
    seed: &[u8],
    date_time: Option<u64>,
    dke: Option<&[u8]>,
    count: usize,
) -> Result<Vec<u8>, OperationFailure> {
    let key: &[u8; Gost28147::KEY_BYTES] = key.try_into().map_err(|_| {
        OperationFailure::invalid_argument(format!(
            "The key of the generator is {} bytes, not {}.",
            Gost28147::KEY_BYTES,
            key.len()
        ))
    })?;
    let seed: &[u8; Gost28147::BLOCK_BYTES] = seed.try_into().map_err(|_| {
        OperationFailure::invalid_argument(format!(
            "The seed of the generator is {} bytes, not {}.",
            Gost28147::BLOCK_BYTES,
            seed.len()
        ))
    })?;
    let sbox = match dke {
        Some(dke) => Some(Gost28147::expand_dke(dke)?),
        None => None,
    };
    let mut generator = RandomGenerator::new(key, seed, date_time, sbox.as_ref().map(|sbox| sbox.as_slice()))?;
    let mut bytes = vec![0u8; count];
    generator.fill_bytes(&mut bytes);
    Ok(bytes)
}

// 6.2: GOST 34.311 reversed, most significant byte first.
fn hash_message(message: &[u8], dke: Option<&[u8]>) -> Result<Vec<u8>, OperationFailure> {
    let mut hasher = gost34311::create_hash(dke, None)?;
    Ok(hash_message_with_hasher(message, &mut hasher))
}

fn decompress_public_key(domain: &DomainParameters, public_key: &[u8]) -> Result<CurvePoint, OperationFailure> {
    Ok(domain.curve().decompress_from_bytes(public_key)?)
}

// 12.3: L_D is a multiple of 16 and at least 2 L(n); the shortest when absent.
fn read_signature_bits(domain: &DomainParameters, signature_bits: Option<u32>) -> Result<u32, OperationFailure> {
    let minimum = domain.minimum_signature_bits();
    match signature_bits {
        None => Ok(minimum),
        Some(bits) if bits >= minimum => Ok(bits),
        Some(bits) => Err(OperationFailure::invalid_argument(format!(
            "12.3: L_D = {bits} is below 2 L(n); the shortest signature is {minimum} bits."
        ))),
    }
}

// Big-endian, left-padded to the byte length of `modulus`.
fn to_fixed_bytes(value: &BigUint, modulus: &BigUint) -> Vec<u8> {
    let length = modulus.bits().div_ceil(BYTE_BITS) as usize;
    let bytes = value.to_bytes_be();
    let mut padded = vec![0u8; length.saturating_sub(bytes.len())];
    padded.extend_from_slice(&bytes);
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    const PB_257: NamedCurve = NamedCurve {
        basis: CurveBasis::Polynomial,
        m: 257,
    };
    const ONB_173: NamedCurve = NamedCurve {
        basis: CurveBasis::OptimalNormal,
        m: 173,
    };

    #[test]
    fn a_signature_verifies_on_both_bases_and_a_tampered_one_does_not() {
        for curve in [PB_257, ONB_173] {
            let key = generate_key_pair(curve).unwrap();
            validate_public_key(curve, &key.public_key).unwrap();
            assert_eq!(calculate_public_key(curve, &key.private_key).unwrap(), key.public_key);
            let mut signature = sign_message(curve, &key.private_key, b"message", None, None).unwrap();
            assert!(verify_message(curve, &key.public_key, b"message", None, &signature).unwrap());
            signature[1] ^= 1;
            assert!(!verify_message(curve, &key.public_key, b"message", None, &signature).unwrap());
        }
    }

    #[test]
    fn the_keys_have_fixed_lengths() {
        // n of the 257-bit curve has 256 bits.
        let key = generate_key_pair(PB_257).unwrap();
        assert_eq!(key.private_key.len(), 32);
        assert_eq!(key.public_key.len(), 33);
    }

    #[test]
    fn the_same_e_gives_the_same_signature_and_it_verifies() {
        let key = generate_key_pair(PB_257).unwrap();
        let hash = [0x5A; 32];
        let e = [0x12; 20];
        let first = sign_hash_with_presignature(PB_257, &key.private_key, &hash, &e, Some(576)).unwrap();
        let second = sign_hash_with_presignature(PB_257, &key.private_key, &hash, &e, Some(576)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 72);
        assert!(verify_hash(PB_257, &key.public_key, &hash, &first).unwrap());
    }

    #[test]
    fn decoding_splits_what_encoding_joined() {
        let signature = encode_signature(&[1, 2], &[3, 4], 64).unwrap();
        assert_eq!(signature, [0, 0, 3, 4, 0, 0, 1, 2]);
        let halves = decode_signature(&signature).unwrap();
        assert_eq!((halves.r, halves.s), (vec![1, 2], vec![3, 4]));
    }

    #[test]
    fn the_generator_of_appendix_a_is_deterministic_for_a_fixed_state() {
        let first = generate_random_bytes(&[1; 32], &[2; 8], Some(42), None, 16).unwrap();
        assert_eq!(
            first,
            generate_random_bytes(&[1; 32], &[2; 8], Some(42), None, 16).unwrap()
        );
        assert_ne!(
            first,
            generate_random_bytes(&[1; 32], &[2; 8], Some(43), None, 16).unwrap()
        );
    }

    #[test]
    fn an_unknown_curve_and_a_foreign_key_are_refused() {
        let unknown = NamedCurve {
            basis: CurveBasis::OptimalNormal,
            m: 257,
        };
        assert!(generate_key_pair(unknown).is_err());
        assert!(validate_public_key(PB_257, &[0xFF; 33]).is_err());
        assert!(sign_hash_with_presignature(PB_257, &[1], &[1], &[0], None).is_err());
    }
}
