use std::fmt;

use num_bigint::{BigInt, Sign};
use ua_cryptography_der::{Asn1Node, DerError, tag};

use crate::cms::CmsAttribute;
use crate::x509::{Certificate, DistinguishedName, hex_upper};

/// The context tag of SignerIdentifier.subjectKeyIdentifier, of signedAttrs and of SignedData.certificates.
const SUBJECT_KEY_IDENTIFIER_TAG: u8 = 0;
/// The context tag of SignerInfo.signedAttrs.
const SIGNED_ATTRIBUTES_TAG: u8 = 0;
/// The context tag of SignerInfo.unsignedAttrs.
const UNSIGNED_ATTRIBUTES_TAG: u8 = 1;
/// The position of the first optional field of SignerInfo (after version, sid and digestAlgorithm).
const FIRST_OPTIONAL_FIELD: usize = 3;
/// The digit that, leading a hex number, would make it read as negative.
const FIRST_SIGNED_HEX_DIGIT: char = '8';

/// SignerInfo (RFC 5652, 5.3). The signer is identified by issuer and serial number or by subject key identifier;
/// the signature covers the DER SET OF the signed attributes ([`signed_attributes_for_signature`]), and for DSTU 4145
/// the signature field holds D directly, little-endian (docs/signature-formats.md, section 9).
///
/// [`signed_attributes_for_signature`]: SignerInfo::signed_attributes_for_signature
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    encoded: Vec<u8>,
    version: i32,
    issuer: Option<DistinguishedName>,
    serial_number: Option<BigInt>,
    subject_key_identifier: Option<Vec<u8>>,
    digest_algorithm: String,
    signed_attributes_for_signature: Option<Vec<u8>>,
    signed_attributes: Vec<CmsAttribute>,
    signature_algorithm: String,
    signature: Vec<u8>,
    unsigned_attributes: Vec<CmsAttribute>,
}

impl SignerInfo {
    /// Reads one SignerInfo.
    pub(crate) fn from_asn1(node: &Asn1Node<'_>) -> Result<Self, DerError> {
        let fields = node.children()?;
        let field = |index: usize| node.child(index);
        let sid = field(1)?;
        let (issuer, serial_number, subject_key_identifier) = if sid.has_tag(tag::SEQUENCE) {
            let issuer = DistinguishedName::from_asn1(&sid.child(0)?)?;
            (Some(issuer), Some(sid.child(1)?.to_integer()?), None)
        } else if sid.is_context(SUBJECT_KEY_IDENTIFIER_TAG) {
            (None, None, Some(sid.to_octet_string()?))
        } else {
            (None, None, None)
        };

        let mut index = FIRST_OPTIONAL_FIELD;
        let mut signed_attributes_for_signature = None;
        let mut signed_attributes = Vec::new();
        if field(index)?.is_context(SIGNED_ATTRIBUTES_TAG) {
            // [0] IMPLICIT SET OF Attribute: the signature is over the same bytes with the SET tag (RFC 5652, 5.4).
            let mut attributes = field(index)?.encoded().to_vec();
            attributes[0] = tag::SET;
            signed_attributes_for_signature = Some(attributes);
            signed_attributes = read_attributes(&field(index)?)?;
            index += 1;
        }
        let signature_algorithm = field(index)?.child(0)?.to_oid()?;
        let signature = field(index + 1)?.expect_tag(tag::OCTET_STRING)?.to_octet_string()?;
        let unsigned_attributes = match fields.get(index + 2) {
            Some(unsigned) if unsigned.is_context(UNSIGNED_ATTRIBUTES_TAG) => read_attributes(unsigned)?,
            _ => Vec::new(),
        };
        Ok(Self {
            encoded: node.encoded().to_vec(),
            version: field(0)?.to_i32()?,
            issuer,
            serial_number,
            subject_key_identifier,
            digest_algorithm: field(2)?.child(0)?.to_oid()?,
            signed_attributes_for_signature,
            signed_attributes,
            signature_algorithm,
            signature,
            unsigned_attributes,
        })
    }

    /// The DER SignerInfo.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// The version: 1 (issuer and serial number) or 3 (subject key identifier).
    pub fn version(&self) -> i32 {
        self.version
    }

    /// The issuer named by issuerAndSerialNumber.
    pub fn issuer(&self) -> Option<&DistinguishedName> {
        self.issuer.as_ref()
    }

    /// The serial number named by issuerAndSerialNumber.
    pub fn serial_number(&self) -> Option<&BigInt> {
        self.serial_number.as_ref()
    }

    /// The subjectKeyIdentifier the signer is named by.
    pub fn subject_key_identifier(&self) -> Option<&[u8]> {
        self.subject_key_identifier.as_deref()
    }

    /// The digest algorithm OID.
    pub fn digest_algorithm(&self) -> &str {
        &self.digest_algorithm
    }

    /// The DER SET OF signed attributes as hashed for the signature, or none when there are none.
    pub fn signed_attributes_for_signature(&self) -> Option<&[u8]> {
        self.signed_attributes_for_signature.as_deref()
    }

    /// The signed attributes.
    pub fn signed_attributes(&self) -> &[CmsAttribute] {
        &self.signed_attributes
    }

    /// The signature algorithm OID.
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    /// The signature value (for DSTU 4145, D little-endian).
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The unsigned attributes.
    pub fn unsigned_attributes(&self) -> &[CmsAttribute] {
        &self.unsigned_attributes
    }

    /// The signed attribute of this type, if present.
    pub fn find_signed(&self, oid: &str) -> Option<&CmsAttribute> {
        self.signed_attributes.iter().find(|attribute| attribute.oid == oid)
    }

    /// The unsigned attribute of this type, if present.
    pub fn find_unsigned(&self, oid: &str) -> Option<&CmsAttribute> {
        self.unsigned_attributes.iter().find(|attribute| attribute.oid == oid)
    }

    /// True when the signer identifier names `certificate`.
    pub fn identifies(&self, certificate: &Certificate) -> bool {
        if let Some(identifier) = &self.subject_key_identifier {
            return certificate.subject_key_identifier().as_ref() == Some(identifier);
        }
        self.serial_number.as_ref() == Some(certificate.serial_number())
            && self.issuer.as_ref() == Some(certificate.issuer())
    }
}

impl fmt::Display for SignerInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(identifier) = &self.subject_key_identifier {
            return write!(formatter, "key identifier {}", hex_upper(identifier));
        }
        match (&self.serial_number, &self.issuer) {
            (Some(serial), Some(issuer)) => {
                write!(formatter, "serial number {} issued by {issuer}", signed_hex(serial))
            }
            _ => write!(formatter, "an unidentified signer"),
        }
    }
}

fn read_attributes(set: &Asn1Node<'_>) -> Result<Vec<CmsAttribute>, DerError> {
    let mut attributes = Vec::new();
    for attribute in set.children()? {
        let values = attribute.child(1)?.expect_tag(tag::SET)?.children()?;
        attributes.push(CmsAttribute {
            oid: attribute.child(0)?.to_oid()?,
            values: values.iter().map(|value| value.encoded().to_vec()).collect(),
        });
    }
    Ok(attributes)
}

// Hex as a signed big integer prints it: a leading 0 when the first digit would read as negative.
fn signed_hex(value: &BigInt) -> String {
    if value.sign() == Sign::Minus {
        return hex_upper(&value.to_signed_bytes_be());
    }
    let digits = format!("{:X}", value.magnitude());
    if digits.starts_with(|digit: char| digit >= FIRST_SIGNED_HEX_DIGIT && digit.is_ascii_hexdigit()) {
        format!("0{digits}")
    } else {
        digits
    }
}
