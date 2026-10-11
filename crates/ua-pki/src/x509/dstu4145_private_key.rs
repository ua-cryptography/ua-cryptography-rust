use std::fmt;

use num_bigint::BigUint;
use num_traits::Zero;
use ua_der::{Asn1Node, tag};
use ua_dstu4145::{DomainParameters, Signer};
use ua_gost::DEFAULT_DKE;

use crate::algorithms;
use crate::errors::{KeyError, SigningError};
use crate::x509::Dstu4145PublicKey;
use crate::x509::key_algorithm::{self, reversed, to_fixed};

/// The PKCS#8 version.
const PKCS8_VERSION: i64 = 0;
/// The bits of one octet.
const BYTE_BITS: u64 = 8;

/// A DSTU 4145 private key with its domain parameters and DKE. Signs raw hashes by the national convention
/// (docs/signature-formats.md, section 1): the hash is reversed before 5.9 and D = S‖R is returned little-endian.
///
/// d is a `BigUint` and is not wiped from memory; the byte buffers this type creates are.
#[derive(Clone)]
pub struct Dstu4145PrivateKey {
    domain: DomainParameters,
    d: BigUint,
    dke: Option<Vec<u8>>,
    is_little_endian: bool,
    public_key: Dstu4145PublicKey,
}

impl Dstu4145PrivateKey {
    /// The key d on `domain`; refuses d outside (0, n).
    pub fn new(
        domain: DomainParameters,
        d: BigUint,
        dke: Option<Vec<u8>>,
        is_little_endian: bool,
    ) -> Result<Self, KeyError> {
        let q = Signer::new(&domain)
            .calculate_public_key(&d)
            .map_err(|_| KeyError::PrivateKeyOutOfRange)?;
        let public_key = Dstu4145PublicKey::new(domain.clone(), q, dke.clone(), is_little_endian);
        Ok(Self {
            domain,
            d,
            dke,
            is_little_endian,
            public_key,
        })
    }

    /// A fresh key on `domain` (clause 9) from the OS generator, with DKE No. 1 written explicitly.
    pub fn generate(domain: &DomainParameters) -> Self {
        let pair = Signer::new(domain).generate_key_pair();
        let dke = Some(DEFAULT_DKE.to_vec());
        let public_key = Dstu4145PublicKey::new(domain.clone(), pair.public_key, dke.clone(), true);
        Self {
            domain: domain.clone(),
            d: pair.private_key,
            dke,
            is_little_endian: true,
            public_key,
        }
    }

    /// The domain parameters.
    pub fn domain(&self) -> &DomainParameters {
        &self.domain
    }

    /// The private key d.
    pub fn d(&self) -> &BigUint {
        &self.d
    }

    /// The GOST 34.311 DKE, or none (DKE No. 1).
    pub fn dke(&self) -> Option<&[u8]> {
        self.dke.as_deref()
    }

    /// True for the little-endian key OID.
    pub fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    /// Q = −dP (clause 9) with the same parameters and DKE.
    pub fn public_key(&self) -> &Dstu4145PublicKey {
        &self.public_key
    }

    /// Signs a raw hash (as the hash function outputs it) and returns D little-endian.
    pub fn sign_hash(&self, raw_hash: &[u8]) -> Result<Vec<u8>, SigningError> {
        let mut signature = Signer::new(&self.domain)
            .sign_hash(&self.d, &reversed(raw_hash))
            .map_err(SigningError::Dstu4145)?;
        signature.reverse();
        Ok(signature)
    }

    /// Hashes `data` with the hash of `signature_algorithm` (GOST 34.311 with this key's DKE) and signs.
    pub fn sign(&self, signature_algorithm: &str, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        let hash_oid = algorithms::hash_of_signature_algorithm(signature_algorithm)?;
        self.sign_hash(&algorithms::hash(hash_oid, data, self.dke())?)
    }

    /// PrivateKeyInfo (RFC 5208) as stored in JKS by Ukrainian banks: version 0, the key AlgorithmIdentifier and d as
    /// an OCTET STRING of ⌈L(n)/8⌉ bytes in the byte order of the key OID.
    pub fn to_pkcs8(&self) -> Result<Vec<u8>, KeyError> {
        let mut d = to_fixed(&self.d, scalar_length(&self.domain), self.is_little_endian);
        let algorithm = key_algorithm::encode_algorithm(&self.domain, self.dke(), self.is_little_endian);
        let pkcs8 = algorithm.map(|algorithm| {
            ua_der::sequence([
                ua_der::integer_from_i64(PKCS8_VERSION),
                algorithm,
                ua_der::octet_string(&d),
            ])
        });
        d.fill(0);
        pkcs8
    }

    /// Parses PrivateKeyInfo. Besides the raw octet string of d, the BouncyCastle form (an OCTET STRING holding a
    /// DER INTEGER, big-endian) is accepted; the two are told apart by their length.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, KeyError> {
        let info = Asn1Node::parse(pkcs8)?.expect_tag(tag::SEQUENCE)?;
        let algorithm = key_algorithm::parse_algorithm(&info.child(1)?)?;
        let mut raw = info.child(2)?.expect_tag(tag::OCTET_STRING)?.to_octet_string()?;
        let d = read_scalar(&raw, &algorithm.domain, algorithm.is_little_endian);
        raw.fill(0);
        let d = d.ok_or(KeyError::PrivateKeyOutOfRange)?;
        if d.is_zero() || &d >= algorithm.domain.n() {
            return Err(KeyError::PrivateKeyOutOfRange);
        }
        Self::new(algorithm.domain, d, algorithm.dke, algorithm.is_little_endian)
    }
}

impl fmt::Debug for Dstu4145PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Dstu4145PrivateKey")
            .field("domain", &self.domain)
            .field("d", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

// d from its octet string, or from the DER INTEGER BouncyCastle writes there; none for a negative INTEGER.
fn read_scalar(raw: &[u8], domain: &DomainParameters, is_little_endian: bool) -> Option<BigUint> {
    if raw.len() != scalar_length(domain) {
        let integer = Asn1Node::parse(raw).ok().filter(|node| node.has_tag(tag::INTEGER));
        if let Some(integer) = integer {
            return integer.to_unsigned_integer().ok();
        }
    }
    Some(if is_little_endian {
        BigUint::from_bytes_le(raw)
    } else {
        BigUint::from_bytes_be(raw)
    })
}

fn scalar_length(domain: &DomainParameters) -> usize {
    ua_dstu4145::bit_length(domain.n()).div_ceil(BYTE_BITS) as usize
}
