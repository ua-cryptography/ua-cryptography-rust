use time::OffsetDateTime;
use ua_cryptography_der::{Asn1Node, DerError, tag};

use crate::algorithms;
use crate::errors::{AlgorithmError, OcspError};
use crate::ocsp::{OcspCertificateStatus, OcspSingleResponse};
use crate::oids;
use crate::x509::{Certificate, DistinguishedName};

/// OCSPResponseStatus successful.
const SUCCESSFUL: u8 = 0;
/// The context tag of ResponseData.version (EXPLICIT, DEFAULT v1).
const VERSION_TAG: u8 = 0;
/// The context tag of ResponderID byName.
const BY_NAME_TAG: u8 = 1;
/// The context tag of ResponderID byKey.
const BY_KEY_TAG: u8 = 2;
/// The context tag of BasicOCSPResponse.certs and of OCSPResponse.responseBytes.
const CERTS_TAG: u8 = 0;
/// The context tag of CertStatus good.
const GOOD_TAG: u8 = 0;
/// The context tag of CertStatus revoked.
const REVOKED_TAG: u8 = 1;
/// The context tag of SingleResponse.nextUpdate.
const NEXT_UPDATE_TAG: u8 = 0;
/// The context tag of TBSRequest.requestExtensions.
const REQUEST_EXTENSIONS_TAG: u8 = 2;
/// The position of SingleResponse.nextUpdate, after certID, certStatus and thisUpdate.
const NEXT_UPDATE_INDEX: usize = 3;
/// The fields of BasicOCSPResponse without the certificates.
const BASIC_FIELDS_WITHOUT_CERTS: usize = 3;

/// A BasicOCSPResponse (RFC 6960, 4.2.1) as used in the national PKI (docs/signature-formats.md, section 5): signed
/// over the DER tbsResponseData, the signature value is a BIT STRING wrapping an OCTET STRING with D, the responder
/// is identified by name or key hash and its certificate travels in the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspResponse {
    basic_encoded: Vec<u8>,
    tbs_response_data: Vec<u8>,
    responder_id_encoded: Vec<u8>,
    responder_name: Option<DistinguishedName>,
    responder_key_hash: Option<Vec<u8>>,
    produced_at: OffsetDateTime,
    responses: Vec<OcspSingleResponse>,
    signature_algorithm: String,
    signature_value: Vec<u8>,
    certificates: Vec<Certificate>,
}

impl OcspResponse {
    /// Parses a full OCSPResponse; refuses it unless its status is successful and it holds a basic response.
    pub fn load(data: &[u8]) -> Result<Self, OcspError> {
        let response = Asn1Node::parse(data)?.expect_tag(tag::SEQUENCE)?;
        let status = response.child(0)?.expect_tag(tag::ENUMERATED)?;
        let status = *status.content().first().ok_or(DerError::EmptyInteger)?;
        if status != SUCCESSFUL {
            return Err(OcspError::Refused { status });
        }
        let bytes = response.child(1)?.child(0)?;
        let response_type = bytes.child(0)?.to_oid()?;
        if response_type != oids::OCSP_BASIC {
            return Err(OcspError::UnsupportedResponseType { oid: response_type });
        }
        Self::load_basic(&bytes.child(1)?.to_octet_string()?)
    }

    /// Parses a BasicOCSPResponse, as CAdES revocationValues stores it.
    pub fn load_basic(data: &[u8]) -> Result<Self, OcspError> {
        let node = Asn1Node::parse(data)?.expect_tag(tag::SEQUENCE)?;
        let fields = node.children()?;
        let tbs = node.child(0)?.expect_tag(tag::SEQUENCE)?;
        let certificates = match fields.get(BASIC_FIELDS_WITHOUT_CERTS) {
            Some(certs) if certs.is_context(CERTS_TAG) => certs
                .child(0)?
                .children()?
                .iter()
                .map(|certificate| Certificate::load(certificate.encoded()))
                .collect::<Result<Vec<_>, _>>()?,
            _ => Vec::new(),
        };
        let tbs_fields = tbs.children()?;
        let mut index = usize::from(tbs_fields.first().is_some_and(|field| field.is_context(VERSION_TAG)));
        let responder = tbs.child(index)?;
        let (responder_name, responder_key_hash) = read_responder_id(&responder)?;
        let produced_at = tbs.child(index + 1)?.to_time()?;
        index += 2;
        let responses = tbs
            .child(index)?
            .children()?
            .iter()
            .map(read_single)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            basic_encoded: data.to_vec(),
            tbs_response_data: tbs.encoded().to_vec(),
            responder_id_encoded: responder.encoded().to_vec(),
            responder_name,
            responder_key_hash,
            produced_at,
            responses,
            signature_algorithm: node.child(1)?.child(0)?.to_oid()?,
            signature_value: node.child(2)?.to_bit_string()?.to_vec(),
            certificates,
        })
    }

    /// The DER BasicOCSPResponse.
    pub fn basic_encoded(&self) -> &[u8] {
        &self.basic_encoded
    }

    /// The full OCSPResponse ("successful", id-pkix-ocsp-basic), as stored in XAdES and PDF.
    pub fn full_encoded(&self) -> Vec<u8> {
        let bytes = ua_cryptography_der::sequence([
            ua_cryptography_der::object_identifier(oids::OCSP_BASIC),
            ua_cryptography_der::octet_string(&self.basic_encoded),
        ]);
        ua_cryptography_der::sequence([
            ua_cryptography_der::encode(tag::ENUMERATED, &[SUCCESSFUL]),
            ua_cryptography_der::explicit(CERTS_TAG, &bytes),
        ])
    }

    /// The DER tbsResponseData, the bytes covered by the signature.
    pub fn tbs_response_data(&self) -> &[u8] {
        &self.tbs_response_data
    }

    /// The DER ResponderID.
    pub fn responder_id_encoded(&self) -> &[u8] {
        &self.responder_id_encoded
    }

    /// The responder's name, when it is identified by name.
    pub fn responder_name(&self) -> Option<&DistinguishedName> {
        self.responder_name.as_ref()
    }

    /// The SHA-1 hash of the responder's key, when it is identified by key.
    pub fn responder_key_hash(&self) -> Option<&[u8]> {
        self.responder_key_hash.as_deref()
    }

    /// producedAt.
    pub fn produced_at(&self) -> OffsetDateTime {
        self.produced_at
    }

    /// The single responses.
    pub fn responses(&self) -> &[OcspSingleResponse] {
        &self.responses
    }

    /// The signature algorithm OID.
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }

    /// The signature BIT STRING value (a DER OCTET STRING with D).
    pub fn signature_value(&self) -> &[u8] {
        &self.signature_value
    }

    /// The certificates the response carries.
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// The response about `certificate`, if this response has one.
    pub fn find(&self, certificate: &Certificate, issuer: &Certificate) -> Option<&OcspSingleResponse> {
        self.responses.iter().find(|single| single.matches(certificate, issuer))
    }

    /// The responder's certificate: in the response or among `known`, by name or by key hash.
    pub fn find_responder(&self, known: &[Certificate]) -> Option<Certificate> {
        self.certificates
            .iter()
            .chain(known)
            .find(|candidate| self.names_responder(candidate))
            .cloned()
    }

    /// True when the response is signed by `responder` over tbsResponseData.
    pub fn is_signed_by(&self, responder: &Certificate) -> bool {
        let d = Asn1Node::parse(&self.signature_value)
            .and_then(|node| node.expect_tag(tag::OCTET_STRING))
            .and_then(|node| node.to_octet_string());
        match (d, responder.public_key()) {
            (Ok(d), Ok(key)) => key
                .verify(&self.signature_algorithm, &self.tbs_response_data, &d)
                .is_ok_and(|is_valid| is_valid),
            _ => false,
        }
    }

    /// OCSPRequest for one certificate with a nonce: CertID hashes the issuer's name and key with `hash_oid`.
    pub fn create_request(
        certificate: &Certificate,
        issuer: &Certificate,
        hash_oid: &str,
        nonce: &[u8],
    ) -> Result<Vec<u8>, AlgorithmError> {
        let cert_id = ua_cryptography_der::sequence([
            ua_cryptography_der::algorithm_identifier(hash_oid),
            ua_cryptography_der::octet_string(&algorithms::hash(hash_oid, issuer.subject().encoded(), None)?),
            ua_cryptography_der::octet_string(&algorithms::hash(hash_oid, issuer.public_key_bits(), None)?),
            ua_cryptography_der::integer(certificate.serial_number()),
        ]);
        let nonce_extension = ua_cryptography_der::sequence([
            ua_cryptography_der::object_identifier(oids::OCSP_NONCE),
            ua_cryptography_der::octet_string(&ua_cryptography_der::octet_string(nonce)),
        ]);
        let tbs_request = ua_cryptography_der::sequence([
            ua_cryptography_der::sequence([ua_cryptography_der::sequence([cert_id])]),
            ua_cryptography_der::explicit(
                REQUEST_EXTENSIONS_TAG,
                &ua_cryptography_der::sequence([nonce_extension]),
            ),
        ]);
        Ok(ua_cryptography_der::sequence([tbs_request]))
    }

    fn names_responder(&self, candidate: &Certificate) -> bool {
        if let Some(name) = &self.responder_name {
            return candidate.subject() == name;
        }
        let Some(key_hash) = &self.responder_key_hash else {
            return false;
        };
        candidate.subject_key_identifier().as_ref() == Some(key_hash)
            || algorithms::hash(oids::SHA1, candidate.public_key_bits(), None).is_ok_and(|hash| &hash == key_hash)
    }
}

fn read_responder_id(responder: &Asn1Node<'_>) -> Result<(Option<DistinguishedName>, Option<Vec<u8>>), DerError> {
    if responder.is_context(BY_NAME_TAG) {
        return Ok((Some(DistinguishedName::from_asn1(&responder.child(0)?)?), None));
    }
    if responder.is_context(BY_KEY_TAG) {
        return Ok((None, Some(responder.child(0)?.to_octet_string()?)));
    }
    Ok((None, None))
}

// SingleResponse ::= SEQUENCE { certID, certStatus CHOICE { good [0] NULL, revoked [1] RevokedInfo, unknown [2] NULL },
//                               thisUpdate GeneralizedTime, nextUpdate [0] EXPLICIT OPTIONAL, singleExtensions [1] }
fn read_single(single: &Asn1Node<'_>) -> Result<OcspSingleResponse, DerError> {
    let cert_id = single.child(0)?;
    let status = single.child(1)?;
    let (status_value, revocation_time) = if status.is_context(GOOD_TAG) {
        (OcspCertificateStatus::Good, None)
    } else if status.is_context(REVOKED_TAG) {
        // [1] IMPLICIT RevokedInfo { revocationTime, revocationReason }
        (OcspCertificateStatus::Revoked, Some(status.child(0)?.to_time()?))
    } else {
        (OcspCertificateStatus::Unknown, None)
    };
    let fields = single.children()?;
    let next_update = match fields.get(NEXT_UPDATE_INDEX) {
        Some(next) if next.is_context(NEXT_UPDATE_TAG) => Some(next.child(0)?.to_time()?),
        _ => None,
    };
    Ok(OcspSingleResponse {
        hash_algorithm: cert_id.child(0)?.child(0)?.to_oid()?,
        issuer_name_hash: cert_id.child(1)?.to_octet_string()?,
        issuer_key_hash: cert_id.child(2)?.to_octet_string()?,
        serial_number: cert_id.child(3)?.to_integer()?,
        status: status_value,
        this_update: single.child(2)?.to_time()?,
        next_update,
        revocation_time,
    })
}
