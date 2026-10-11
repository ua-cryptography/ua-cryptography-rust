//! The verifying side of the national PKI conventions written independently of `ua_pki`'s verifiers: hashes by OID,
//! DSTU 4145 keys read from SubjectPublicKeyInfo with `ua-der`, and the checks of certificates, CMS signers,
//! time-stamps and OCSP responses with `ua-dstu4145` directly (the role BouncyCastle recipes play in the C# tests).

use num_bigint::BigUint;
use ua_der::{Asn1Node, tag};
use ua_dstu4145::{DomainParameters, Signer};
use ua_gf2m::{BinaryCurve, BinaryField, CurvePoint};
use ua_pki::oids;

/// The hash of `data` by OID; GOST 34.311 uses `dke` or DKE No. 1.
pub fn hash(oid: &str, data: &[u8], dke: Option<&[u8]>) -> Vec<u8> {
    match oid {
        oids::GOST34311 => match dke {
            Some(dke) => ua_gost::Gost34311::from_dke(dke).unwrap().hash(data).to_vec(),
            None => ua_gost::Gost34311::calculate_hash(data).to_vec(),
        },
        oids::DSTU7564_256 => ua_dstu7564::Kupyna::calculate_hash(data, ua_dstu7564::HashSize::Bits256),
        _ => panic!("hash {oid}"),
    }
}

/// The hash a signature algorithm stands for.
pub fn hash_of(signature_algorithm: &str) -> &'static str {
    match signature_algorithm {
        oids::DSTU4145_WITH_DSTU7564 => oids::DSTU7564_256,
        oids::DSTU4145_WITH_GOST34311 => oids::GOST34311,
        _ => panic!("signature algorithm {signature_algorithm}"),
    }
}

pub fn reversed(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().rev().copied().collect()
}

/// A DSTU 4145 key as SubjectPublicKeyInfo carries it.
pub struct PublicKey {
    pub domain: DomainParameters,
    pub q: CurvePoint,
    pub dke: Option<Vec<u8>>,
}

/// Reads the key of a DER certificate: a named curve of table Г.1 or explicit ECBinary parameters (section 8 checked).
pub fn read_public_key(certificate: &[u8]) -> PublicKey {
    let certificate = Asn1Node::parse(certificate).unwrap();
    let spki = certificate
        .child(0)
        .unwrap()
        .children()
        .unwrap()
        .into_iter()
        .find(is_spki)
        .unwrap();
    let algorithm = spki.child(0).unwrap();
    let is_little_endian = algorithm.child(0).unwrap().to_oid().unwrap() == oids::DSTU4145_LE;
    let parameters = algorithm.child(1).unwrap().children().unwrap();
    let dke = parameters.get(1).map(|node| node.to_octet_string().unwrap());
    let domain = if parameters[0].has_tag(tag::OBJECT_IDENTIFIER) {
        let oid = parameters[0].to_oid().unwrap();
        let index: usize = oid.rsplit('.').next().unwrap().parse().unwrap();
        ua_dstu4145::get_polynomial_curve_by_index(index).unwrap()
    } else {
        read_explicit(&parameters[0], is_little_endian)
    };
    let bits = spki.child(1).unwrap().to_bit_string().unwrap();
    let mut q = Asn1Node::parse(bits).unwrap().to_octet_string().unwrap();
    if is_little_endian {
        q.reverse();
    }
    let q = domain.curve().decompress(&BigUint::from_bytes_be(&q)).unwrap();
    domain.validate_public_key(&q).unwrap();
    PublicKey { domain, q, dke }
}

// SubjectPublicKeyInfo is the TBSCertificate field whose first child is an AlgorithmIdentifier of a DSTU 4145 key.
fn is_spki(node: &Asn1Node<'_>) -> bool {
    node.has_tag(tag::SEQUENCE)
        && node
            .child(0)
            .and_then(|algorithm| algorithm.child(0))
            .and_then(|oid| oid.to_oid())
            .is_ok_and(|oid| oid == oids::DSTU4145_LE || oid == oids::DSTU4145_BE)
}

fn read_explicit(ec: &Asn1Node<'_>, is_little_endian: bool) -> DomainParameters {
    let fields = ec.children().unwrap();
    let field_node = fields[0].children().unwrap();
    let m = field_node[0].to_i32().unwrap() as u32;
    let field = if field_node[1].has_tag(tag::INTEGER) {
        BinaryField::polynomial(m, field_node[1].to_i32().unwrap() as u32, 0, 0).unwrap()
    } else {
        let p = field_node[1].children().unwrap();
        let exponent = |i: usize| p[i].to_i32().unwrap() as u32;
        BinaryField::polynomial(m, exponent(0), exponent(1), exponent(2)).unwrap()
    };
    let a = fields[1].to_i32().unwrap() as u32;
    let mut b = fields[2].to_octet_string().unwrap();
    let n = fields[3].to_unsigned_integer().unwrap();
    let mut g = fields[4].to_octet_string().unwrap();
    if is_little_endian {
        b.reverse();
        g.reverse();
    }
    let curve = BinaryCurve::from_biguint(&field, a, &BigUint::from_bytes_be(&b)).unwrap();
    let base_point = curve.decompress(&BigUint::from_bytes_be(&g)).unwrap();
    let domain = DomainParameters::new(&curve, &base_point, &n).unwrap();
    domain.validate().unwrap();
    domain
}

/// The national convention: the hash is reversed before 5.9 and D is stored little-endian.
pub fn verify_dstu4145(key: &PublicKey, raw_hash: &[u8], signature: &[u8]) -> bool {
    Signer::new(&key.domain).verify_hash(&key.q, &reversed(raw_hash), &reversed(signature))
}

/// Signatures of certificates and OCSP responses: a BIT STRING that wraps an OCTET STRING with D.
pub fn unwrap_signature(bit_string: &[u8]) -> Vec<u8> {
    Asn1Node::parse(bit_string)
        .unwrap()
        .expect_tag(tag::OCTET_STRING)
        .unwrap()
        .to_octet_string()
        .unwrap()
}

/// The certificate is signed by the issuer's key; GOST 34.311 takes the issuer's DKE.
pub fn verify_certificate(certificate: &[u8], issuer: &[u8]) -> bool {
    let node = Asn1Node::parse(certificate).unwrap();
    let tbs = node.child(0).unwrap().encoded();
    let algorithm = node.child(1).unwrap().child(0).unwrap().to_oid().unwrap();
    let signature = unwrap_signature(node.child(2).unwrap().to_bit_string().unwrap());
    let key = read_public_key(issuer);
    verify_dstu4145(&key, &hash(hash_of(&algorithm), tbs, key.dke.as_deref()), &signature)
}

/// Subject and issuer DER names of a certificate.
pub fn names(certificate: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let tbs = Asn1Node::parse(certificate).unwrap().child(0).unwrap();
    let first = usize::from(tbs.child(0).unwrap().is_context(0));
    let issuer = tbs.child(first + 2).unwrap().encoded().to_vec();
    let subject = tbs.child(first + 4).unwrap().encoded().to_vec();
    (subject, issuer)
}

/// Walks issuer links by name from `leaf`, verifying each, up to a self-signed root that must be in `trusted`.
pub fn chains_to_trusted(leaf: &[u8], pool: &[Vec<u8>], trusted: &[Vec<u8>]) -> bool {
    let mut current = leaf.to_vec();
    for _ in 0..10 {
        let (subject, issuer) = names(&current);
        if subject == issuer {
            return verify_certificate(&current, &current) && trusted.contains(&current);
        }
        let Some(next) = pool
            .iter()
            .find(|candidate| names(candidate).0 == issuer && **candidate != current)
        else {
            return false;
        };
        if !verify_certificate(&current, next) {
            return false;
        }
        current = next.clone();
    }
    false
}

/// One SignerInfo read with `ua-der`.
pub struct CmsSigner {
    pub digest_algorithm: String,
    pub signature_algorithm: String,
    pub signed_attributes: Vec<u8>,
    pub signature: Vec<u8>,
    pub serial_number: num_bigint::BigInt,
    pub attributes: Vec<(String, Vec<u8>)>,
    pub unsigned: Vec<(String, Vec<u8>)>,
}

/// A CMS ContentInfo read with `ua-der`: content type, content, certificates, signers.
pub struct Cms {
    pub content_type: String,
    pub content: Option<Vec<u8>>,
    pub certificates: Vec<Vec<u8>>,
    pub signers: Vec<CmsSigner>,
}

pub fn read_cms(der: &[u8]) -> Cms {
    let content_info = Asn1Node::parse(der).unwrap();
    assert_eq!(content_info.child(0).unwrap().to_oid().unwrap(), oids::SIGNED_DATA);
    let signed_data = content_info.child(1).unwrap().child(0).unwrap();
    let fields = signed_data.children().unwrap();
    let encapsulated = &fields[2];
    let content = encapsulated
        .child(1)
        .ok()
        .map(|explicit| explicit.child(0).unwrap().to_octet_string().unwrap());
    let certificates = fields
        .iter()
        .find(|field| field.is_context(0))
        .map(|set| set.children().unwrap().iter().map(|c| c.encoded().to_vec()).collect())
        .unwrap_or_default();
    let signers = fields
        .last()
        .unwrap()
        .children()
        .unwrap()
        .iter()
        .map(read_signer)
        .collect();
    Cms {
        content_type: encapsulated.child(0).unwrap().to_oid().unwrap(),
        content,
        certificates,
        signers,
    }
}

fn read_signer(node: &Asn1Node<'_>) -> CmsSigner {
    let fields = node.children().unwrap();
    let mut signed = fields[3].encoded().to_vec();
    signed[0] = tag::SET;
    let attributes_of = |set: &Asn1Node<'_>| -> Vec<(String, Vec<u8>)> {
        set.children()
            .unwrap()
            .iter()
            .map(|attribute| {
                let value = attribute.child(1).unwrap().child(0).unwrap().encoded().to_vec();
                (attribute.child(0).unwrap().to_oid().unwrap(), value)
            })
            .collect()
    };
    CmsSigner {
        serial_number: fields[1].child(1).unwrap().to_integer().unwrap(),
        digest_algorithm: fields[2].child(0).unwrap().to_oid().unwrap(),
        attributes: attributes_of(&fields[3]),
        signature_algorithm: fields[4].child(0).unwrap().to_oid().unwrap(),
        signature: fields[5].to_octet_string().unwrap(),
        unsigned: fields.get(6).map(attributes_of).unwrap_or_default(),
        signed_attributes: signed,
    }
}

impl CmsSigner {
    pub fn signed(&self, oid: &str) -> &[u8] {
        &self
            .attributes
            .iter()
            .find(|(id, _)| id == oid)
            .unwrap_or_else(|| panic!("signed {oid}"))
            .1
    }

    pub fn unsigned(&self, oid: &str) -> &[u8] {
        &self
            .unsigned
            .iter()
            .find(|(id, _)| id == oid)
            .unwrap_or_else(|| panic!("unsigned {oid}"))
            .1
    }

    pub fn message_digest(&self) -> Vec<u8> {
        Asn1Node::parse(self.signed(oids::MESSAGE_DIGEST))
            .unwrap()
            .to_octet_string()
            .unwrap()
    }
}

/// signingCertificateV2 names the certificate, and the signature over the DER signed attributes verifies.
pub fn verify_cms_signer(signer: &CmsSigner, certificate: &[u8]) -> bool {
    let attribute = Asn1Node::parse(signer.signed(oids::SIGNING_CERTIFICATE_V2)).unwrap();
    let cert_id = attribute.child(0).unwrap().child(0).unwrap();
    let hash_oid = cert_id.child(0).unwrap().child(0).unwrap().to_oid().unwrap();
    if hash(&hash_oid, certificate, None) != cert_id.child(1).unwrap().to_octet_string().unwrap() {
        return false;
    }
    let key = read_public_key(certificate);
    verify_dstu4145(
        &key,
        &hash(&signer.digest_algorithm, &signer.signed_attributes, None),
        &signer.signature,
    )
}

/// The TSTInfo of a token after checking that its messageDigest covers it: (imprint algorithm, imprint, policy).
pub fn read_time_stamp(token: &[u8]) -> (String, Vec<u8>, String) {
    let cms = read_cms(token);
    assert_eq!(cms.content_type, oids::TST_INFO);
    let content = cms.content.unwrap();
    assert_eq!(cms.signers.len(), 1);
    let signer = &cms.signers[0];
    assert_eq!(hash(&signer.digest_algorithm, &content, None), signer.message_digest());
    let info = Asn1Node::parse(&content).unwrap();
    let imprint = info.child(2).unwrap();
    (
        imprint.child(0).unwrap().child(0).unwrap().to_oid().unwrap(),
        imprint.child(1).unwrap().to_octet_string().unwrap(),
        info.child(1).unwrap().to_oid().unwrap(),
    )
}

/// The token's imprint is the hash of `covered`.
pub fn imprint_covers(token: &[u8], covered: &[u8]) -> bool {
    let (algorithm, imprint, _) = read_time_stamp(token);
    hash(&algorithm, covered, None) == imprint
}

/// A BasicOCSPResponse inside a full OCSPResponse whose status is successful.
pub fn read_ocsp_response(full: &[u8]) -> Vec<u8> {
    let response = Asn1Node::parse(full).unwrap();
    assert_eq!(response.child(0).unwrap().content(), [0]);
    let bytes = response.child(1).unwrap().child(0).unwrap();
    assert_eq!(bytes.child(0).unwrap().to_oid().unwrap(), oids::OCSP_BASIC);
    bytes.child(1).unwrap().to_octet_string().unwrap()
}

/// The responder's certificate of a BasicOCSPResponse (by name), in the response or among `known`.
pub fn find_ocsp_responder(basic: &[u8], known: &[Vec<u8>]) -> Vec<u8> {
    let node = Asn1Node::parse(basic).unwrap();
    let tbs = node.child(0).unwrap();
    let responder = tbs.children().unwrap().into_iter().find(|f| f.is_context(1)).unwrap();
    let name = responder.child(0).unwrap().encoded().to_vec();
    let inside: Vec<Vec<u8>> = node
        .child(3)
        .map(|certs| {
            certs
                .child(0)
                .unwrap()
                .children()
                .unwrap()
                .iter()
                .map(|c| c.encoded().to_vec())
                .collect()
        })
        .unwrap_or_default();
    inside
        .iter()
        .chain(known)
        .find(|certificate| names(certificate).0 == name)
        .unwrap()
        .clone()
}

/// The response is signed by the responder over the DER tbsResponseData.
pub fn verify_ocsp(basic: &[u8], responder: &[u8]) -> bool {
    let node = Asn1Node::parse(basic).unwrap();
    let tbs = node.child(0).unwrap().encoded();
    let algorithm = node.child(1).unwrap().child(0).unwrap().to_oid().unwrap();
    let signature = unwrap_signature(node.child(2).unwrap().to_bit_string().unwrap());
    let key = read_public_key(responder);
    verify_dstu4145(&key, &hash(hash_of(&algorithm), tbs, key.dke.as_deref()), &signature)
}

/// The single responses of a BasicOCSPResponse: (serial number, status tag).
pub fn ocsp_statuses(basic: &[u8]) -> Vec<(num_bigint::BigInt, u8)> {
    let tbs = Asn1Node::parse(basic).unwrap().child(0).unwrap();
    let fields = tbs.children().unwrap();
    let responses = fields.iter().find(|f| f.has_tag(tag::SEQUENCE)).unwrap();
    responses
        .children()
        .unwrap()
        .iter()
        .map(|single| {
            let serial = single.child(0).unwrap().child(3).unwrap().to_integer().unwrap();
            (serial, single.child(1).unwrap().tag() & 0x1F)
        })
        .collect()
}

/// The serial number of a DER certificate.
pub fn serial_number(certificate: &[u8]) -> num_bigint::BigInt {
    let tbs = Asn1Node::parse(certificate).unwrap().child(0).unwrap();
    let first = usize::from(tbs.child(0).unwrap().is_context(0));
    tbs.child(first).unwrap().to_integer().unwrap()
}
