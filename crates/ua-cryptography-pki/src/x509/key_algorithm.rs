//! The DSTU 4145 key AlgorithmIdentifier `{ key OID, SEQUENCE { curve, DKE OPTIONAL } }` of SubjectPublicKeyInfo and
//! PKCS#8 (docs/signature-formats.md, section 3), and the octet-string conventions of the keys.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use num_bigint::BigUint;
use ua_cryptography_der::{Asn1Node, tag};
use ua_cryptography_dstu4145::{DomainParameters, POLYNOMIAL_DEGREES};
use ua_cryptography_gf2m::{BinaryCurve, BinaryField, FieldBasis};
use ua_cryptography_gost::Gost34311;

use crate::errors::KeyError;
use crate::oids;

/// Explicit parameters kept after their checks of section 8; the cache is emptied when it reaches this size.
const MAX_CACHED_DOMAINS: usize = 64;
/// Tables 1 and 2 of DSTU 4145-2002 start at this degree.
const MIN_FIELD_DEGREE: i32 = 163;
/// Tables 1 and 2 of DSTU 4145-2002 end at this degree; a larger field would only make section 8 expensive.
const MAX_FIELD_DEGREE: i32 = 509;
/// The bits of one octet.
const BYTE_BITS: usize = 8;
/// The cache key prefix of little-endian explicit parameters.
const LITTLE_ENDIAN_MARK: u8 = 1;
/// The cache key prefix of big-endian explicit parameters.
const BIG_ENDIAN_MARK: u8 = 0;

/// What the key AlgorithmIdentifier says.
pub(crate) struct KeyAlgorithm {
    pub(crate) domain: DomainParameters,
    pub(crate) dke: Option<Vec<u8>>,
    pub(crate) is_little_endian: bool,
}

/// True for the two DSTU 4145 key OIDs.
pub(crate) fn is_dstu4145(algorithm_oid: &str) -> bool {
    algorithm_oid == oids::DSTU4145_LE || algorithm_oid == oids::DSTU4145_BE
}

/// Parses the key AlgorithmIdentifier of SubjectPublicKeyInfo or PKCS#8; explicit parameters are checked by section 8.
pub(crate) fn parse_algorithm(algorithm: &Asn1Node<'_>) -> Result<KeyAlgorithm, KeyError> {
    let algorithm = algorithm.expect_tag(tag::SEQUENCE)?;
    let oid = algorithm.child(0)?.to_oid()?;
    if !is_dstu4145(&oid) {
        return Err(KeyError::NotDstu4145 { oid });
    }
    let is_little_endian = oid == oids::DSTU4145_LE;
    let parameters = algorithm.child(1)?.expect_tag(tag::SEQUENCE)?.children()?;
    let dke = match parameters.get(1) {
        Some(node) => Some(read_dke(node)?),
        None => None,
    };
    let curve = parameters.first().ok_or(ua_cryptography_der::DerError::MissingChild {
        tag: tag::SEQUENCE,
        count: 0,
        index: 0,
    })?;
    let domain = if curve.has_tag(tag::OBJECT_IDENTIFIER) {
        named_curve(&curve.to_oid()?)?
    } else {
        parse_explicit(curve, is_little_endian)?
    };
    Ok(KeyAlgorithm {
        domain,
        dke,
        is_little_endian,
    })
}

/// The key AlgorithmIdentifier: named polynomial-basis curves of table Г.1 are written by OID, any other explicitly.
pub(crate) fn encode_algorithm(
    domain: &DomainParameters,
    dke: Option<&[u8]>,
    is_little_endian: bool,
) -> Result<Vec<u8>, KeyError> {
    let curve = match named_curve_index(domain) {
        Some(index) => ua_cryptography_der::object_identifier(&format!("{}{index}", oids::NAMED_CURVE_PREFIX)),
        None => encode_explicit(domain, is_little_endian)?,
    };
    let parameters = match dke {
        Some(table) => ua_cryptography_der::sequence([curve, ua_cryptography_der::octet_string(table)]),
        None => ua_cryptography_der::sequence([curve]),
    };
    let key_oid = if is_little_endian {
        oids::DSTU4145_LE
    } else {
        oids::DSTU4145_BE
    };
    Ok(ua_cryptography_der::sequence([
        ua_cryptography_der::object_identifier(key_oid),
        parameters,
    ]))
}

/// The index of a curve in table Г.1, or none when the parameters are not one of them.
pub(crate) fn named_curve_index(domain: &DomainParameters) -> Option<usize> {
    if !matches!(domain.field().basis(), FieldBasis::Polynomial(_)) {
        return None;
    }
    let index = POLYNOMIAL_DEGREES.iter().position(|&m| m == domain.field().m())?;
    let named = ua_cryptography_dstu4145::get_polynomial_curve_by_index(index).ok()?;
    (&named == domain).then_some(index)
}

/// A non-negative integer as exactly `length` bytes in the requested byte order.
///
/// # Panics
/// If the value does not fit: the callers pass field elements and scalars of the key's own size.
pub(crate) fn to_fixed(value: &BigUint, length: usize, is_little_endian: bool) -> Vec<u8> {
    let mut little_endian = value.to_bytes_le();
    assert!(
        little_endian.len() <= length,
        "the value does not fit into {length} bytes"
    );
    little_endian.resize(length, 0);
    if !is_little_endian {
        little_endian.reverse();
    }
    little_endian
}

/// The bytes in reverse order (the national convention for hashes and signatures, section 1).
pub(crate) fn reversed(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

/// The bytes of a field element of degree m.
pub(crate) fn field_bytes(m: u32) -> usize {
    (m as usize).div_ceil(BYTE_BITS)
}

fn read_dke(node: &Asn1Node<'_>) -> Result<Vec<u8>, KeyError> {
    let dke = node.expect_tag(tag::OCTET_STRING)?.to_octet_string()?;
    Gost34311::from_dke(&dke).map_err(KeyError::InvalidDke)?;
    Ok(dke)
}

fn named_curve(oid: &str) -> Result<DomainParameters, KeyError> {
    let unknown = || KeyError::UnknownNamedCurve { oid: oid.to_owned() };
    let index: usize = oid
        .strip_prefix(oids::NAMED_CURVE_PREFIX)
        .and_then(|suffix| suffix.parse().ok())
        .ok_or_else(unknown)?;
    ua_cryptography_dstu4145::get_polynomial_curve_by_index(index).map_err(|_| unknown())
}

// ECBinary ::= SEQUENCE { version [0] EXPLICIT INTEGER DEFAULT 0, f BinaryField, a INTEGER, b OCTET STRING,
//                         n INTEGER, bp OCTET STRING }
fn parse_explicit(ec: &Asn1Node<'_>, is_little_endian: bool) -> Result<DomainParameters, KeyError> {
    let mut cache_key = vec![if is_little_endian {
        LITTLE_ENDIAN_MARK
    } else {
        BIG_ENDIAN_MARK
    }];
    cache_key.extend_from_slice(ec.encoded());
    let cache = explicit_domains();
    if let Some(cached) = cache.lock().unwrap_or_else(PoisonError::into_inner).get(&cache_key) {
        return Ok(cached.clone());
    }

    let fields = ec.expect_tag(tag::SEQUENCE)?.children()?;
    let first = usize::from(fields.first().is_some_and(|node| node.is_context(0)));
    let field_of = |index: usize| fields.get(first + index).ok_or(missing_field(index));
    let field = parse_binary_field(field_of(0)?)?;
    let a = field_of(1)?.to_i32()?;
    let mut b = field_of(2)?.expect_tag(tag::OCTET_STRING)?.to_octet_string()?;
    let n = field_of(3)?.to_unsigned_integer()?;
    let mut g = field_of(4)?.expect_tag(tag::OCTET_STRING)?.to_octet_string()?;
    if is_little_endian {
        b.reverse();
        g.reverse();
    }
    let a = u32::try_from(a)
        .map_err(|_| KeyError::InvalidCurve(ua_cryptography_gf2m::CurveError::CoefficientANotZeroOrOne))?;
    let curve = BinaryCurve::from_biguint(&field, a, &BigUint::from_bytes_be(&b)).map_err(KeyError::InvalidCurve)?;
    let base_point = curve
        .decompress(&BigUint::from_bytes_be(&g))
        .map_err(KeyError::InvalidPoint)?;
    let domain = DomainParameters::new(&curve, &base_point, &n).map_err(KeyError::InvalidDomain)?;
    let domain = named_or_checked(domain)?;

    let mut domains = cache.lock().unwrap_or_else(PoisonError::into_inner);
    if domains.len() >= MAX_CACHED_DOMAINS {
        domains.clear();
    }
    domains.insert(cache_key, domain.clone());
    Ok(domain)
}

// BinaryField ::= SEQUENCE { m INTEGER, CHOICE { k INTEGER, SEQUENCE { k, j, l } } OPTIONAL } — absent: ONB.
fn parse_binary_field(node: &Asn1Node<'_>) -> Result<BinaryField, KeyError> {
    let parts = node.expect_tag(tag::SEQUENCE)?.children()?;
    let m = parts.first().ok_or(missing_field(0))?.to_i32()?;
    if !(MIN_FIELD_DEGREE..=MAX_FIELD_DEGREE).contains(&m) {
        return Err(KeyError::UnsupportedFieldDegree { m: i64::from(m) });
    }
    let m = m.unsigned_abs();
    let field = match parts.get(1) {
        None => BinaryField::optimal_normal(m),
        Some(k) if k.has_tag(tag::INTEGER) => BinaryField::polynomial(m, exponent(k)?, 0, 0),
        Some(pentanomial) => {
            let exponents = pentanomial.expect_tag(tag::SEQUENCE)?.children()?;
            let exponent_at = |index: usize| exponents.get(index).ok_or(missing_field(index)).map(exponent);
            BinaryField::polynomial(m, exponent_at(0)??, exponent_at(1)??, exponent_at(2)??)
        }
    };
    field.map_err(KeyError::InvalidField)
}

fn exponent(node: &Asn1Node<'_>) -> Result<u32, KeyError> {
    let value = node.to_i32()?;
    u32::try_from(value).map_err(|_| KeyError::Der(ua_cryptography_der::DerError::IntegerOutOfRange))
}

// The parameters of table Г.1 are the named curves themselves; anything else must pass section 8.
fn named_or_checked(domain: DomainParameters) -> Result<DomainParameters, KeyError> {
    let named = named_curve_index(&domain)
        .and_then(|index| ua_cryptography_dstu4145::get_polynomial_curve_by_index(index).ok());
    if let Some(named) = named {
        return Ok(named);
    }
    domain.validate().map_err(KeyError::InvalidDomainParameters)?;
    Ok(domain)
}

fn encode_explicit(domain: &DomainParameters, is_little_endian: bool) -> Result<Vec<u8>, KeyError> {
    let m = domain.field().m();
    let bytes = field_bytes(m);
    let field = match domain.field().basis() {
        FieldBasis::Polynomial(basis) if basis.is_trinomial() => ua_cryptography_der::sequence([
            ua_cryptography_der::integer_from_i64(i64::from(m)),
            ua_cryptography_der::integer_from_i64(i64::from(basis.k())),
        ]),
        FieldBasis::Polynomial(basis) => ua_cryptography_der::sequence([
            ua_cryptography_der::integer_from_i64(i64::from(m)),
            ua_cryptography_der::sequence([
                ua_cryptography_der::integer_from_i64(i64::from(basis.k())),
                ua_cryptography_der::integer_from_i64(i64::from(basis.j())),
                ua_cryptography_der::integer_from_i64(i64::from(basis.l())),
            ]),
        ]),
        FieldBasis::OptimalNormal(_) => {
            ua_cryptography_der::sequence([ua_cryptography_der::integer_from_i64(i64::from(m))])
        }
    };
    let curve = domain.curve();
    let a = i64::from(!curve.a().is_zero());
    let base_point = curve
        .compress(domain.base_point())
        .map_err(|_| KeyError::NoCompressedForm)?;
    Ok(ua_cryptography_der::sequence([
        field,
        ua_cryptography_der::integer_from_i64(a),
        ua_cryptography_der::octet_string(&to_fixed(&curve.b().to_biguint(), bytes, is_little_endian)),
        ua_cryptography_der::integer_from_unsigned(domain.n()),
        ua_cryptography_der::octet_string(&to_fixed(&base_point, bytes, is_little_endian)),
    ]))
}

fn missing_field(index: usize) -> KeyError {
    KeyError::Der(ua_cryptography_der::DerError::MissingChild {
        tag: tag::SEQUENCE,
        count: index,
        index,
    })
}

fn explicit_domains() -> &'static Mutex<HashMap<Vec<u8>, DomainParameters>> {
    static DOMAINS: OnceLock<Mutex<HashMap<Vec<u8>, DomainParameters>>> = OnceLock::new();
    DOMAINS.get_or_init(|| Mutex::new(HashMap::new()))
}
