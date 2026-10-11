//! Builds CMS SignedData with one DSTU 4145 signer, shared by CAdES signatures and time-stamp tokens. The signed
//! attributes are contentType, messageDigest and signingCertificateV2 plus any extra ones; the signature covers their
//! DER SET OF, and SignerInfo.signature holds D little-endian (docs/signature-formats.md, section 9).

use crate::algorithms;
use crate::errors::{AlgorithmError, SigningError};
use crate::oids;
use crate::signing_key::SigningKey;
use crate::x509::Certificate;

/// The SignerInfo version with issuerAndSerialNumber.
const SIGNER_INFO_VERSION: i64 = 1;
/// The SignedData version over id-data.
const DATA_VERSION: i64 = 1;
/// The SignedData version over another content type (RFC 5652, 5.1).
const OTHER_CONTENT_VERSION: i64 = 3;
/// The context tag of GeneralName.directoryName.
const DIRECTORY_NAME_TAG: u8 = 4;
/// The context tag of signedAttrs, of eContent, of certificates and of ContentInfo.content.
const ZERO_TAG: u8 = 0;
/// The context tag of unsignedAttrs.
const UNSIGNED_ATTRIBUTES_TAG: u8 = 1;

/// An Attribute ::= SEQUENCE { attrType, SET OF value }.
pub fn attribute<T: AsRef<[u8]>>(oid: &str, values: impl IntoIterator<Item = T>) -> Vec<u8> {
    ua_der::sequence([ua_der::object_identifier(oid), ua_der::set_of(values)])
}

/// signingCertificateV2 (RFC 5035): one ESSCertIDv2 with the hash of the certificate, the algorithm written out, and
/// issuerSerial — the issuer as a directoryName and the serial number — as IIT and the banks write it.
pub fn signing_certificate_v2(certificate: &Certificate, hash_oid: &str) -> Result<Vec<u8>, AlgorithmError> {
    let cert_id = ua_der::sequence([
        ua_der::algorithm_identifier(hash_oid),
        ua_der::octet_string(&algorithms::hash(hash_oid, certificate.encoded(), None)?),
        issuer_serial(certificate),
    ]);
    Ok(attribute(
        oids::SIGNING_CERTIFICATE_V2,
        [ua_der::sequence([ua_der::sequence([cert_id])])],
    ))
}

/// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber }, the issuer as GeneralName directoryName `[4]`.
pub fn issuer_serial(certificate: &Certificate) -> Vec<u8> {
    let issuer = ua_der::sequence([ua_der::explicit(DIRECTORY_NAME_TAG, certificate.issuer().encoded())]);
    ua_der::sequence([issuer, ua_der::integer(certificate.serial_number())])
}

/// The DER SET OF signed attributes for `content`: contentType, the extra attributes, messageDigest and
/// signingCertificateV2. GOST 34.311 uses the signer's DKE.
pub fn signed_attributes(
    content: &[u8],
    content_type: &str,
    signer: &SigningKey,
    hash_oid: &str,
    extra: &[Vec<u8>],
) -> Result<Vec<u8>, AlgorithmError> {
    let mut attributes = vec![attribute(oids::CONTENT_TYPE, [ua_der::object_identifier(content_type)])];
    attributes.extend(extra.iter().cloned());
    let digest = algorithms::hash(hash_oid, content, signer.key().dke())?;
    attributes.push(attribute(oids::MESSAGE_DIGEST, [ua_der::octet_string(&digest)]));
    attributes.push(signing_certificate_v2(signer.certificate(), hash_oid)?);
    Ok(ua_der::set_of(attributes))
}

/// SignerInfo version 1 with issuerAndSerialNumber, signing `signed_attributes` (a DER SET); returns the SignerInfo
/// and the signature value.
pub fn signer_info(
    signed_attributes: &[u8],
    signer: &SigningKey,
    hash_oid: &str,
    unsigned_attributes: &[Vec<u8>],
) -> Result<(Vec<u8>, Vec<u8>), SigningError> {
    let hash = algorithms::hash(hash_oid, signed_attributes, signer.key().dke())?;
    let signature = signer.key().sign_hash(&hash)?;
    let info = signer_info_with(
        signed_attributes,
        &signature,
        signer.certificate(),
        hash_oid,
        unsigned_attributes,
    )?;
    Ok((info, signature))
}

/// The same SignerInfo fields with a given signature value and unsigned attributes.
pub fn signer_info_with(
    signed_attributes: &[u8],
    signature: &[u8],
    certificate: &Certificate,
    hash_oid: &str,
    unsigned_attributes: &[Vec<u8>],
) -> Result<Vec<u8>, AlgorithmError> {
    let mut fields = vec![
        ua_der::integer_from_i64(SIGNER_INFO_VERSION),
        ua_der::sequence([
            certificate.issuer().encoded().to_vec(),
            ua_der::integer(certificate.serial_number()),
        ]),
        ua_der::algorithm_identifier(hash_oid),
        ua_der::implicit(ZERO_TAG, signed_attributes),
        ua_der::algorithm_identifier(algorithms::signature_algorithm_for(hash_oid)?),
        ua_der::octet_string(signature),
    ];
    if !unsigned_attributes.is_empty() {
        fields.push(ua_der::implicit(
            UNSIGNED_ATTRIBUTES_TAG,
            &ua_der::set_of(unsigned_attributes),
        ));
    }
    Ok(ua_der::sequence(fields))
}

/// ContentInfo { SignedData } with one signer; the content is encapsulated unless `encapsulated` is none. Repeated
/// certificates are written once.
pub fn signed_data(
    signer_info: &[u8],
    hash_oid: &str,
    content_type: &str,
    encapsulated: Option<&[u8]>,
    certificates: &[Certificate],
) -> Vec<u8> {
    let encap_content_info = match encapsulated {
        Some(content) => ua_der::sequence([
            ua_der::object_identifier(content_type),
            ua_der::explicit(ZERO_TAG, &ua_der::octet_string(content)),
        ]),
        None => ua_der::sequence([ua_der::object_identifier(content_type)]),
    };
    let version = if content_type == oids::DATA {
        DATA_VERSION
    } else {
        OTHER_CONTENT_VERSION
    };
    let mut fields = vec![
        ua_der::integer_from_i64(version),
        ua_der::set_of([ua_der::algorithm_identifier(hash_oid)]),
        encap_content_info,
    ];
    let mut distinct: Vec<&Certificate> = Vec::new();
    for certificate in certificates {
        if !distinct.contains(&certificate) {
            distinct.push(certificate);
        }
    }
    if !distinct.is_empty() {
        let encodings = distinct.iter().map(|certificate| certificate.encoded());
        fields.push(ua_der::implicit(ZERO_TAG, &ua_der::set_of(encodings)));
    }
    fields.push(ua_der::set_of([signer_info]));
    ua_der::sequence([
        ua_der::object_identifier(oids::SIGNED_DATA),
        ua_der::explicit(ZERO_TAG, &ua_der::sequence(fields)),
    ])
}
