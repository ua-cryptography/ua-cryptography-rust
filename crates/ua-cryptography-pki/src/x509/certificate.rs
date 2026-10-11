use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

use num_bigint::BigInt;
use time::OffsetDateTime;
use ua_cryptography_der::{Asn1Node, DerError, tag};

use crate::errors::{CertificateError, KeyError};
use crate::oids;
use crate::x509::{CertificateExtension, DistinguishedName, Dstu4145PublicKey};

/// The version number of an X.509 v1 certificate (no version field).
const VERSION_1: i32 = 1;
/// The context tag of TBSCertificate.version.
const VERSION_TAG: u8 = 0;
/// The context tag of TBSCertificate.extensions.
const EXTENSIONS_TAG: u8 = 3;
/// The context tag of AuthorityKeyIdentifier.keyIdentifier.
const KEY_IDENTIFIER_TAG: u8 = 0;
/// The context tag of GeneralName.uniformResourceIdentifier.
const URI_TAG: u8 = 6;
/// An extension with the critical flag has three fields.
const CRITICAL_EXTENSION_FIELDS: usize = 3;

/// An X.509 certificate (RFC 5280) read with `ua-cryptography-der`. The DSTU 4145 key is decoded on first use, so
/// certificates with other key types can still be parsed, listed and matched. Two certificates are equal when their DER
/// is.
#[derive(Debug, Clone)]
pub struct Certificate {
    encoded: Vec<u8>,
    tbs_encoded: Vec<u8>,
    version: i32,
    serial_number: BigInt,
    issuer: DistinguishedName,
    subject: DistinguishedName,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    signature_algorithm: String,
    signature_value: Vec<u8>,
    subject_public_key_info: Vec<u8>,
    public_key_algorithm: String,
    public_key_bits: Vec<u8>,
    extensions: Vec<CertificateExtension>,
    public_key: OnceLock<Result<Dstu4145PublicKey, KeyError>>,
}

impl Certificate {
    /// Parses a DER certificate, or PEM / bare base64 text holding one.
    pub fn load(data: &[u8]) -> Result<Self, CertificateError> {
        let der = ua_cryptography_der::decode_pem(data, "CERTIFICATE")?;
        Ok(parse_certificate(der)?)
    }

    /// The DER encoding.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// The DER TBSCertificate, the bytes covered by the signature.
    pub fn tbs_encoded(&self) -> &[u8] {
        &self.tbs_encoded
    }

    /// The version: 1, 2 or 3.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// The serial number.
    pub fn serial_number(&self) -> &BigInt {
        &self.serial_number
    }

    /// The issuer's name.
    pub fn issuer(&self) -> &DistinguishedName {
        &self.issuer
    }

    /// The subject's name.
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject
    }

    /// The start of the validity period.
    pub fn not_before(&self) -> OffsetDateTime {
        self.not_before
    }

    /// The end of the validity period.
    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    /// The signature algorithm OID.
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    /// The signatureValue BIT STRING (for DSTU 4145, a DER OCTET STRING with D, little-endian).
    pub fn signature_value(&self) -> &[u8] {
        &self.signature_value
    }

    /// The DER SubjectPublicKeyInfo.
    pub fn subject_public_key_info(&self) -> &[u8] {
        &self.subject_public_key_info
    }

    /// The key algorithm OID.
    pub fn public_key_algorithm(&self) -> &str {
        &self.public_key_algorithm
    }

    /// The subjectPublicKey BIT STRING value (what the OCSP CertID's issuerKeyHash covers).
    pub fn public_key_bits(&self) -> &[u8] {
        &self.public_key_bits
    }

    /// The extensions in the order of the certificate.
    pub fn extensions(&self) -> &[CertificateExtension] {
        &self.extensions
    }

    /// True when the key is a DSTU 4145 key.
    pub fn has_dstu4145_key(&self) -> bool {
        Dstu4145PublicKey::is_dstu4145(&self.public_key_algorithm)
    }

    /// The DSTU 4145 key, checked by section 8 (parameters) and 10.1 (point); decoded once.
    pub fn public_key(&self) -> Result<&Dstu4145PublicKey, KeyError> {
        let decoded = self.public_key.get_or_init(|| {
            if !self.has_dstu4145_key() {
                return Err(KeyError::NotDstu4145Certificate {
                    subject: self.subject.to_string(),
                    oid: self.public_key_algorithm.clone(),
                });
            }
            Dstu4145PublicKey::from_subject_public_key_info(&self.subject_public_key_info)
        });
        decoded.as_ref().map_err(Clone::clone)
    }

    /// True when the subject and the issuer are the same name.
    pub fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }

    /// The extension with this OID, if present.
    pub fn find_extension(&self, oid: &str) -> Option<&CertificateExtension> {
        self.extensions.iter().find(|extension| extension.oid == oid)
    }

    /// basicConstraints cA (RFC 5280, 4.2.1.9); a malformed extension reads as absent.
    pub fn is_ca(&self) -> bool {
        let Some(extension) = self.find_extension(oids::BASIC_CONSTRAINTS) else {
            return false;
        };
        let is_ca = || -> Result<bool, DerError> {
            let constraints = Asn1Node::parse(&extension.value)?.children()?;
            match constraints.first() {
                Some(flag) if flag.has_tag(tag::BOOLEAN) => flag.to_boolean(),
                _ => Ok(false),
            }
        };
        is_ca().is_ok_and(|is_ca| is_ca)
    }

    /// keyUsage bits (RFC 5280, 4.2.1.3; bit 0 digitalSignature, 1 nonRepudiation, 5 keyCertSign), or none when
    /// absent or malformed.
    pub fn key_usage(&self) -> Option<u32> {
        let extension = self.find_extension(oids::KEY_USAGE)?;
        Asn1Node::parse(&extension.value)
            .and_then(|bits| bits.to_named_bits())
            .ok()
    }

    /// The extended key usage OIDs; empty when absent or malformed.
    pub fn extended_key_usage(&self) -> Vec<String> {
        let Some(extension) = self.find_extension(oids::EXTENDED_KEY_USAGE) else {
            return Vec::new();
        };
        let purposes = || -> Result<Vec<String>, DerError> {
            Asn1Node::parse(&extension.value)?
                .children()?
                .iter()
                .map(Asn1Node::to_oid)
                .collect()
        };
        purposes().into_iter().flatten().collect()
    }

    /// The subjectKeyIdentifier, if present and well-formed.
    pub fn subject_key_identifier(&self) -> Option<Vec<u8>> {
        let extension = self.find_extension(oids::SUBJECT_KEY_IDENTIFIER)?;
        let identifier = Asn1Node::parse(&extension.value).and_then(|node| node.expect_tag(tag::OCTET_STRING));
        identifier.and_then(|node| node.to_octet_string()).ok()
    }

    /// The keyIdentifier of authorityKeyIdentifier, if present and well-formed.
    pub fn authority_key_identifier(&self) -> Option<Vec<u8>> {
        let extension = self.find_extension(oids::AUTHORITY_KEY_IDENTIFIER)?;
        let fields = Asn1Node::parse(&extension.value)
            .and_then(|node| node.children())
            .ok()?;
        let key_identifier = fields.iter().find(|field| field.is_context(KEY_IDENTIFIER_TAG))?;
        key_identifier.to_octet_string().ok()
    }

    /// OCSP responder URLs (authorityInfoAccess, id-ad-ocsp).
    pub fn ocsp_urls(&self) -> Vec<String> {
        self.access_urls(oids::AUTHORITY_INFO_ACCESS, oids::ACCESS_OCSP)
    }

    /// Where the issuer's certificate can be downloaded (authorityInfoAccess, id-ad-caIssuers).
    pub fn ca_issuer_urls(&self) -> Vec<String> {
        self.access_urls(oids::AUTHORITY_INFO_ACCESS, oids::ACCESS_CA_ISSUERS)
    }

    /// The time-stamping service of the CA (subjectInfoAccess, id-ad-timeStamping), as Ukrainian CAs publish it.
    pub fn time_stamp_urls(&self) -> Vec<String> {
        self.access_urls(oids::SUBJECT_INFO_ACCESS, oids::ACCESS_TIME_STAMPING)
    }

    /// Verifies this certificate's signature with the issuer's key (section 4): the hash comes from the signature
    /// algorithm, GOST 34.311 uses the issuer's DKE. Anything unreadable is a signature that does not verify.
    pub fn is_signed_by(&self, issuer: &Certificate) -> bool {
        let d = Asn1Node::parse(&self.signature_value)
            .and_then(|node| node.expect_tag(tag::OCTET_STRING))
            .and_then(|node| node.to_octet_string());
        match (d, issuer.public_key()) {
            (Ok(d), Ok(key)) => key
                .verify(&self.signature_algorithm, &self.tbs_encoded, &d)
                .is_ok_and(|is_valid| is_valid),
            _ => false,
        }
    }

    /// True when `time` is within the validity period.
    pub fn is_valid_at(&self, time: OffsetDateTime) -> bool {
        time >= self.not_before && time <= self.not_after
    }

    // The uniformResourceIdentifier [6] IA5String locations of `method` in an AccessDescription sequence.
    fn access_urls(&self, extension_oid: &str, method: &str) -> Vec<String> {
        let Some(extension) = self.find_extension(extension_oid) else {
            return Vec::new();
        };
        let urls = || -> Result<Vec<String>, DerError> {
            let mut urls = Vec::new();
            for description in Asn1Node::parse(&extension.value)?.children()? {
                let location = description.child(1)?;
                if description.child(0)?.to_oid()? == method
                    && location.is_context(URI_TAG)
                    && !location.is_constructed()
                {
                    urls.push(String::from_utf8_lossy(location.content()).into_owned());
                }
            }
            Ok(urls)
        };
        urls().into_iter().flatten().collect()
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for Certificate {}

impl Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.encoded.hash(state);
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.subject)
    }
}

fn parse_certificate(encoded: Vec<u8>) -> Result<Certificate, DerError> {
    let certificate = Asn1Node::parse(&encoded)?.expect_tag(tag::SEQUENCE)?;
    let tbs = certificate.child(0)?.expect_tag(tag::SEQUENCE)?;
    let signature_algorithm = certificate.child(1)?.child(0)?.to_oid()?;
    let signature_value = certificate.child(2)?.to_bit_string()?.to_vec();
    let fields = tbs.children()?;
    let field = |index: usize| tbs.child(index);

    let mut index = 0;
    let version = if fields.first().is_some_and(|node| node.is_context(VERSION_TAG)) {
        index += 1;
        field(0)?.child(0)?.to_i32()?.saturating_add(1)
    } else {
        VERSION_1
    };
    let serial_number = field(index)?.to_integer()?;
    index += 2; // the signature AlgorithmIdentifier repeats the outer one
    let issuer = DistinguishedName::from_asn1(&field(index)?)?;
    let validity = field(index + 1)?;
    let subject = DistinguishedName::from_asn1(&field(index + 2)?)?;
    let spki = field(index + 3)?.expect_tag(tag::SEQUENCE)?;
    let extensions = read_extensions(&fields[(index + 4).min(fields.len())..])?;

    Ok(Certificate {
        tbs_encoded: tbs.encoded().to_vec(),
        version,
        serial_number,
        issuer,
        subject,
        not_before: validity.child(0)?.to_time()?,
        not_after: validity.child(1)?.to_time()?,
        signature_algorithm,
        signature_value,
        subject_public_key_info: spki.encoded().to_vec(),
        public_key_algorithm: spki.child(0)?.child(0)?.to_oid()?,
        public_key_bits: spki.child(1)?.to_bit_string()?.to_vec(),
        extensions,
        public_key: OnceLock::new(),
        encoded,
    })
}

// issuerUniqueID [1] and subjectUniqueID [2] are skipped; extensions [3] EXPLICIT SEQUENCE OF Extension.
fn read_extensions(fields: &[Asn1Node<'_>]) -> Result<Vec<CertificateExtension>, DerError> {
    let mut extensions = Vec::new();
    for field in fields.iter().filter(|field| field.is_context(EXTENSIONS_TAG)) {
        for extension in field.child(0)?.expect_tag(tag::SEQUENCE)?.children()? {
            let parts = extension.children()?;
            let is_critical = parts.len() == CRITICAL_EXTENSION_FIELDS && extension.child(1)?.to_boolean()?;
            let value = extension.child(parts.len().saturating_sub(1))?.to_octet_string()?;
            extensions.push(CertificateExtension {
                oid: extension.child(0)?.to_oid()?,
                is_critical,
                value,
            });
        }
    }
    Ok(extensions)
}
