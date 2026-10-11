use num_bigint::BigUint;
use ua_cryptography_der::{Asn1Node, tag};
use ua_cryptography_dstu4145::{DomainParameters, Signer};
use ua_cryptography_gf2m::CurvePoint;

use crate::algorithms;
use crate::errors::{AlgorithmError, KeyError};
use crate::x509::key_algorithm::{self, field_bytes, reversed, to_fixed};

/// A DSTU 4145 public key as carried by SubjectPublicKeyInfo (docs/signature-formats.md, section 3): the domain
/// parameters (a named curve of table Г.1 or an explicit ECBinary structure), the GOST 34.311 DKE when present and
/// the point Q. Two keys are equal when their points are.
#[derive(Debug, Clone)]
pub struct Dstu4145PublicKey {
    domain: DomainParameters,
    q: CurvePoint,
    dke: Option<Vec<u8>>,
    is_little_endian: bool,
}

impl Dstu4145PublicKey {
    /// The key Q on `domain`; `is_little_endian` selects the key OID (little-endian is the national default).
    pub fn new(domain: DomainParameters, q: CurvePoint, dke: Option<Vec<u8>>, is_little_endian: bool) -> Self {
        Self {
            domain,
            q,
            dke,
            is_little_endian,
        }
    }

    /// The domain parameters.
    pub fn domain(&self) -> &DomainParameters {
        &self.domain
    }

    /// The point Q.
    pub fn q(&self) -> &CurvePoint {
        &self.q
    }

    /// The GOST 28147 S-box table for GOST 34.311 hashing (64 bytes), or none (DKE No. 1).
    pub fn dke(&self) -> Option<&[u8]> {
        self.dke.as_deref()
    }

    /// True for [`oids::DSTU4145_LE`](crate::oids::DSTU4145_LE), false for the big-endian OID.
    pub fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    /// True for the two DSTU 4145 key OIDs.
    pub fn is_dstu4145(algorithm_oid: &str) -> bool {
        key_algorithm::is_dstu4145(algorithm_oid)
    }

    /// Verifies a signature D (stored little-endian) over a raw hash by the national convention (section 1).
    pub fn verify_hash(&self, raw_hash: &[u8], signature: &[u8]) -> bool {
        Signer::new(&self.domain).verify_hash(&self.q, &reversed(raw_hash), &reversed(signature))
    }

    /// Verifies a signature over `data` hashed with `hash_oid`, trying each of the
    /// [`candidate_hashes`](algorithms::candidate_hashes); a hash that cannot be computed verifies nothing.
    pub fn verify_data(&self, hash_oid: &str, data: &[u8], signature: &[u8]) -> bool {
        match algorithms::candidate_hashes(hash_oid, data, self.dke()) {
            Ok(hashes) => hashes.iter().any(|hash| self.verify_hash(hash, signature)),
            Err(_) => false,
        }
    }

    /// Hashes `data` with the hash of `signature_algorithm` (GOST 34.311 with this key's DKE) and verifies.
    pub fn verify(&self, signature_algorithm: &str, data: &[u8], signature: &[u8]) -> Result<bool, AlgorithmError> {
        let hash_oid = algorithms::hash_of_signature_algorithm(signature_algorithm)?;
        let hash = algorithms::hash(hash_oid, data, self.dke())?;
        Ok(self.verify_hash(&hash, signature))
    }

    /// Parses DER SubjectPublicKeyInfo; the parameters are checked by section 8 and the key by 10.1.
    pub fn from_subject_public_key_info(spki: &[u8]) -> Result<Self, KeyError> {
        let spki = Asn1Node::parse(spki)?.expect_tag(tag::SEQUENCE)?;
        let algorithm = key_algorithm::parse_algorithm(&spki.child(0)?)?;
        let key_bits = spki.child(1)?.to_bit_string()?;
        let mut q = Asn1Node::parse(key_bits)?
            .expect_tag(tag::OCTET_STRING)?
            .to_octet_string()?;
        if algorithm.is_little_endian {
            q.reverse();
        }
        let curve = algorithm.domain.curve();
        let point = curve
            .decompress(&BigUint::from_bytes_be(&q))
            .map_err(KeyError::InvalidPoint)?;
        algorithm
            .domain
            .validate_public_key(&point)
            .map_err(KeyError::InvalidPublicKey)?;
        Ok(Self::new(
            algorithm.domain,
            point,
            algorithm.dke,
            algorithm.is_little_endian,
        ))
    }

    /// The DER SubjectPublicKeyInfo: the compressed point in an OCTET STRING inside the BIT STRING.
    pub fn to_subject_public_key_info(&self) -> Result<Vec<u8>, KeyError> {
        let compressed = self
            .domain
            .curve()
            .compress(&self.q)
            .map_err(|_| KeyError::NoCompressedForm)?;
        let q = to_fixed(&compressed, field_bytes(self.domain.field().m()), self.is_little_endian);
        let algorithm = key_algorithm::encode_algorithm(&self.domain, self.dke(), self.is_little_endian)?;
        Ok(ua_cryptography_der::sequence([
            algorithm,
            ua_cryptography_der::bit_string(&ua_cryptography_der::octet_string(&q)),
        ]))
    }
}

impl PartialEq for Dstu4145PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.q == other.q
    }
}

impl Eq for Dstu4145PublicKey {}
