use num_bigint::{BigInt, BigUint};
use rand_core::{OsRng, RngCore};
use time::{Duration, OffsetDateTime};
use ua_cryptography_der::{Asn1Node, tag};

use crate::algorithms;
use crate::errors::{KeyError, SigningError};
use crate::oids;
use crate::x509::{Certificate, DistinguishedName, Dstu4145PrivateKey, Dstu4145PublicKey, KeyUsageFlags};

/// The certificate version written: v3.
const VERSION_3: i64 = 2;
/// The bytes of a random serial number.
const SERIAL_NUMBER_BYTES: usize = 8;
/// How far before "now" a new certificate becomes valid, against clock skew.
const VALIDITY_LEAD_MINUTES: i64 = 5;
/// The default validity period.
const DEFAULT_VALIDITY_DAYS: i64 = 365;
/// The context tag of AuthorityKeyIdentifier.keyIdentifier.
const KEY_IDENTIFIER_TAG: u8 = 0;
/// The context tag of GeneralName.uniformResourceIdentifier.
const URI_TAG: u8 = 6;
/// The context tag of TBSCertificate.version.
const VERSION_TAG: u8 = 0;
/// The context tag of TBSCertificate.extensions.
const EXTENSIONS_TAG: u8 = 3;

/// Issues X.509 v3 certificates for DSTU 4145 keys, encoded by the conventions of the Ukrainian PKI
/// (docs/signature-formats.md, section 4): the signature value is a BIT STRING that wraps an OCTET STRING with D
/// (little-endian). Used for self-signed certificates of generated keys and for test hierarchies.
#[derive(Debug, Clone)]
pub struct CertificateBuilder {
    subject: DistinguishedName,
    public_key: Dstu4145PublicKey,
    subject_public_key_info: Vec<u8>,
    extensions: Vec<Vec<u8>>,
    /// The start of the validity period; five minutes ago by default.
    pub not_before: OffsetDateTime,
    /// The end of the validity period; a year from now by default.
    pub not_after: OffsetDateTime,
    /// A positive serial number; random 64 bits by default.
    pub serial_number: BigInt,
    /// [`oids::DSTU4145_WITH_DSTU7564`] (default) or [`oids::DSTU4145_WITH_GOST34311`].
    pub signature_algorithm: String,
}

impl CertificateBuilder {
    /// A builder for `public_key` named `subject`; refuses a key that cannot be written.
    pub fn new(subject: DistinguishedName, public_key: Dstu4145PublicKey) -> Result<Self, KeyError> {
        let now = OffsetDateTime::now_utc();
        let mut serial = [0u8; SERIAL_NUMBER_BYTES];
        OsRng.fill_bytes(&mut serial);
        let serial_number = BigInt::from(BigUint::from_bytes_be(&serial) | BigUint::from(1u8));
        Ok(Self {
            subject_public_key_info: public_key.to_subject_public_key_info()?,
            subject,
            public_key,
            extensions: Vec::new(),
            not_before: now - Duration::minutes(VALIDITY_LEAD_MINUTES),
            not_after: now + Duration::days(DEFAULT_VALIDITY_DAYS),
            serial_number,
            signature_algorithm: oids::DSTU4145_WITH_DSTU7564.to_owned(),
        })
    }

    /// The subject's name.
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject
    }

    /// The key being certified.
    pub fn public_key(&self) -> &Dstu4145PublicKey {
        &self.public_key
    }

    /// Adds an extension with its DER value.
    pub fn add_extension(mut self, oid: &str, is_critical: bool, value: &[u8]) -> Self {
        let extension = if is_critical {
            ua_cryptography_der::sequence([
                ua_cryptography_der::object_identifier(oid),
                ua_cryptography_der::boolean(true),
                ua_cryptography_der::octet_string(value),
            ])
        } else {
            ua_cryptography_der::sequence([
                ua_cryptography_der::object_identifier(oid),
                ua_cryptography_der::octet_string(value),
            ])
        };
        self.extensions.push(extension);
        self
    }

    /// basicConstraints, critical.
    pub fn add_basic_constraints(self, is_ca: bool) -> Self {
        let constraints = if is_ca {
            ua_cryptography_der::sequence([ua_cryptography_der::boolean(true)])
        } else {
            ua_cryptography_der::sequence(Vec::<Vec<u8>>::new())
        };
        self.add_extension(oids::BASIC_CONSTRAINTS, true, &constraints)
    }

    /// keyUsage, critical.
    pub fn add_key_usage(self, usage: KeyUsageFlags) -> Self {
        self.add_extension(oids::KEY_USAGE, true, &ua_cryptography_der::named_bits(usage.0))
    }

    /// extKeyUsage, critical.
    pub fn add_extended_key_usage(self, purposes: &[&str]) -> Self {
        let purposes = ua_cryptography_der::sequence(
            purposes
                .iter()
                .map(|purpose| ua_cryptography_der::object_identifier(purpose)),
        );
        self.add_extension(oids::EXTENDED_KEY_USAGE, true, &purposes)
    }

    /// subjectKeyIdentifier: the DSTU 7564-256 hash of the public key bits (RFC 5280 leaves the method open).
    pub fn add_subject_key_identifier(self) -> Self {
        let identifier = key_identifier_of_spki(&self.subject_public_key_info);
        self.add_extension(
            oids::SUBJECT_KEY_IDENTIFIER,
            false,
            &ua_cryptography_der::octet_string(&identifier),
        )
    }

    /// authorityKeyIdentifier with the issuer's key identifier.
    pub fn add_authority_key_identifier(self, key_identifier: &[u8]) -> Self {
        let value = ua_cryptography_der::sequence([ua_cryptography_der::implicit(
            KEY_IDENTIFIER_TAG,
            &ua_cryptography_der::octet_string(key_identifier),
        )]);
        self.add_extension(oids::AUTHORITY_KEY_IDENTIFIER, false, &value)
    }

    /// authorityInfoAccess with OCSP and/or caIssuers URLs.
    pub fn add_authority_info_access(self, ocsp_url: Option<&str>, ca_issuers_url: Option<&str>) -> Self {
        let mut descriptions = Vec::new();
        if let Some(url) = ocsp_url {
            descriptions.push(access_description(oids::ACCESS_OCSP, url));
        }
        if let Some(url) = ca_issuers_url {
            descriptions.push(access_description(oids::ACCESS_CA_ISSUERS, url));
        }
        self.add_extension(
            oids::AUTHORITY_INFO_ACCESS,
            false,
            &ua_cryptography_der::sequence(descriptions),
        )
    }

    /// subjectInfoAccess with the time-stamping service URL.
    pub fn add_time_stamping_url(self, url: &str) -> Self {
        let value = ua_cryptography_der::sequence([access_description(oids::ACCESS_TIME_STAMPING, url)]);
        self.add_extension(oids::SUBJECT_INFO_ACCESS, false, &value)
    }

    /// The key identifier this builder writes for `key`: DSTU 7564-256 of the subjectPublicKey bits.
    pub fn key_identifier(key: &Dstu4145PublicKey) -> Result<Vec<u8>, KeyError> {
        Ok(key_identifier_of_spki(&key.to_subject_public_key_info()?))
    }

    /// A certificate signed by its own key.
    pub fn self_sign(&self, key: &Dstu4145PrivateKey) -> Result<Certificate, SigningError> {
        self.sign(&self.subject, key)
    }

    /// A certificate issued by `issuer` and signed by its key.
    pub fn issue(&self, issuer: &Certificate, issuer_key: &Dstu4145PrivateKey) -> Result<Certificate, SigningError> {
        self.sign(issuer.subject(), issuer_key)
    }

    fn sign(&self, issuer: &DistinguishedName, signing_key: &Dstu4145PrivateKey) -> Result<Certificate, SigningError> {
        algorithms::hash_of_signature_algorithm(&self.signature_algorithm)?;
        let algorithm = ua_cryptography_der::algorithm_identifier(&self.signature_algorithm);
        let mut tbs = vec![
            ua_cryptography_der::explicit(VERSION_TAG, &ua_cryptography_der::integer_from_i64(VERSION_3)),
            ua_cryptography_der::integer(&self.serial_number),
            algorithm.clone(),
            issuer.encoded().to_vec(),
            ua_cryptography_der::sequence([
                ua_cryptography_der::x509_time(self.not_before),
                ua_cryptography_der::x509_time(self.not_after),
            ]),
            self.subject.encoded().to_vec(),
            self.subject_public_key_info.clone(),
        ];
        if !self.extensions.is_empty() {
            tbs.push(ua_cryptography_der::explicit(
                EXTENSIONS_TAG,
                &ua_cryptography_der::sequence(&self.extensions),
            ));
        }
        let tbs = ua_cryptography_der::sequence(tbs);
        let signature = signing_key.sign(&self.signature_algorithm, &tbs)?;
        let encoded = ua_cryptography_der::sequence([
            tbs,
            algorithm,
            ua_cryptography_der::bit_string(&ua_cryptography_der::octet_string(&signature)),
        ]);
        match Certificate::load(&encoded) {
            Ok(certificate) => Ok(certificate),
            Err(error) => unreachable!("the certificate written must parse: {error}"),
        }
    }
}

fn access_description(method: &str, url: &str) -> Vec<u8> {
    ua_cryptography_der::sequence([
        ua_cryptography_der::object_identifier(method),
        ua_cryptography_der::implicit(URI_TAG, &ua_cryptography_der::ia5_string(url)),
    ])
}

fn key_identifier_of_spki(spki: &[u8]) -> Vec<u8> {
    let bits = Asn1Node::parse(spki)
        .and_then(|node| node.expect_tag(tag::SEQUENCE))
        .and_then(|node| node.child(1))
        .and_then(|node| node.to_bit_string().map(<[u8]>::to_vec));
    match bits {
        Ok(bits) => {
            ua_cryptography_dstu7564::Kupyna::calculate_hash(&bits, ua_cryptography_dstu7564::HashSize::Bits256)
        }
        Err(error) => unreachable!("SubjectPublicKeyInfo written by this crate must parse: {error}"),
    }
}
