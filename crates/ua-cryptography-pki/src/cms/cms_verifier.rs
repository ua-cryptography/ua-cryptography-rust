//! The checks of one CMS signer (docs/signature-formats.md, sections 6 and 9): contentType and messageDigest bind
//! the signed attributes to the content, signingCertificate(V2) binds them to the certificate, and the DSTU 4145
//! signature covers their DER encoding.

use ua_cryptography_der::{Asn1Node, DerError, tag};

use crate::algorithms;
use crate::cms::SignerInfo;
use crate::oids;
use crate::validation::{VerificationReport, certificate_path_validator};
use crate::x509::{Certificate, DistinguishedName};

/// The context tag of GeneralName.directoryName.
const DIRECTORY_NAME_TAG: u8 = 4;
/// IssuerSerial has the issuer and the serial number at least.
const ISSUER_SERIAL_MIN_FIELDS: usize = 2;

/// Adds the checks of `signer` to `report`, their names prefixed with `prefix`.
pub fn verify_signer(
    signer: &SignerInfo,
    certificate: &Certificate,
    content_type: &str,
    content: &[u8],
    report: &mut VerificationReport,
    prefix: &str,
) {
    let Some(signed_attributes) = signer.signed_attributes_for_signature() else {
        report.fail(
            &format!("{prefix}: signed attributes"),
            "the signer has no signed attributes",
        );
        return;
    };
    check_content_type(signer, content_type, report, prefix);
    if !check_message_digest(signer, certificate, content, report, prefix) {
        return;
    }
    check_signing_certificate(signer, certificate, report, prefix);

    let name = format!("{prefix}: signature");
    let key = match certificate.public_key() {
        Ok(key) => key,
        Err(error) => {
            report.fail(&name, &error.to_string());
            return;
        }
    };
    let is_valid = key.verify_data(signer.digest_algorithm(), signed_attributes, signer.signature());
    let details = if is_valid {
        format!(
            "DSTU 4145 signature of {}",
            certificate_path_validator::short(certificate)
        )
    } else {
        "the DSTU 4145 signature does not verify".to_owned()
    };
    report.check(&name, is_valid, &details);
}

/// signingCertificateV2 (or the SHA-1 signingCertificate) names exactly this certificate.
pub fn check_signing_certificate(
    signer: &SignerInfo,
    certificate: &Certificate,
    report: &mut VerificationReport,
    prefix: &str,
) {
    let name = format!("{prefix}: signing certificate");
    let version_2 = signer.find_signed(oids::SIGNING_CERTIFICATE_V2);
    let Some(attribute) = version_2.or_else(|| signer.find_signed(oids::SIGNING_CERTIFICATE)) else {
        report.warn(&name, "neither signingCertificateV2 nor signingCertificate is present");
        return;
    };
    match read_first_cert_id(attribute.value(), version_2.is_some()) {
        Ok(cert_id) => report_cert_id(&cert_id, certificate, report, &name),
        Err(_) => report.fail(&name, "the signed attributes name a different certificate"),
    }
}

/// The first ESSCertID(v2) of a signing certificate attribute.
struct CertId {
    hash_oid: String,
    hash: Vec<u8>,
    issuer_serial: Option<Vec<u8>>,
}

// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
// ESSCertIDv2 ::= SEQUENCE { hashAlgorithm DEFAULT sha256, certHash OCTET STRING, issuerSerial OPTIONAL }
// ESSCertID   ::= SEQUENCE { certHash OCTET STRING, issuerSerial OPTIONAL }
fn read_first_cert_id(value: Option<&[u8]>, is_version_2: bool) -> Result<CertId, DerError> {
    let value = value.ok_or(DerError::Truncated)?;
    let attribute = Asn1Node::parse(value)?;
    let first = attribute.child(0)?.child(0)?;
    let has_algorithm = first.child(0)?.has_tag(tag::SEQUENCE);
    let hash_oid = match (is_version_2, has_algorithm) {
        (false, _) => oids::SHA1.to_owned(),
        (true, true) => first.child(0)?.child(0)?.to_oid()?,
        (true, false) => oids::SHA256.to_owned(),
    };
    let hash_index = usize::from(has_algorithm);
    let fields = first.children()?;
    Ok(CertId {
        hash_oid,
        hash: first.child(hash_index)?.to_octet_string()?,
        issuer_serial: fields.get(hash_index + 1).map(|node| node.encoded().to_vec()),
    })
}

fn report_cert_id(cert_id: &CertId, certificate: &Certificate, report: &mut VerificationReport, name: &str) {
    let dke = certificate_dke(certificate);
    let matches = algorithms::is_supported_hash(&cert_id.hash_oid)
        && algorithms::digest_matches(&cert_id.hash_oid, certificate.encoded(), &cert_id.hash, dke.as_deref());
    if !matches {
        report.fail(name, "the signed attributes name a different certificate");
        return;
    }
    let names_another_issuer = cert_id
        .issuer_serial
        .as_ref()
        .is_some_and(|issuer_serial| !issuer_serial_matches(issuer_serial, certificate));
    if names_another_issuer {
        report.fail(
            name,
            "the hash matches, but issuerSerial names another issuer or serial number",
        );
        return;
    }
    let suffix = if cert_id.issuer_serial.is_some() {
        ", and so do its issuer and serial number"
    } else {
        ""
    };
    let details = format!(
        "{} of the certificate matches{suffix}",
        algorithms::hash_name(&cert_id.hash_oid)
    );
    report.pass(name, &details);
}

// messageDigest is the hash of the content; false when the hash is not supported and the signer cannot be checked.
fn check_message_digest(
    signer: &SignerInfo,
    certificate: &Certificate,
    content: &[u8],
    report: &mut VerificationReport,
    prefix: &str,
) -> bool {
    let digest_algorithm = signer.digest_algorithm();
    let name = format!("{prefix}: messageDigest");
    let Some(digest) = signer.find_signed(oids::MESSAGE_DIGEST) else {
        report.fail(&name, "the attribute is missing");
        return true;
    };
    if !algorithms::is_supported_hash(digest_algorithm) {
        report.fail(&name, &format!("hash algorithm {digest_algorithm} is not supported"));
        return false;
    }
    let dke = certificate_dke(certificate);
    let expected = octet_string_value(digest.value());
    let matches =
        expected.is_ok_and(|expected| algorithms::digest_matches(digest_algorithm, content, &expected, dke.as_deref()));
    let details = if matches {
        format!("{} of the content matches", algorithms::hash_name(digest_algorithm))
    } else {
        "the content does not match the signed hash".to_owned()
    };
    report.check(&name, matches, &details);
    true
}

fn check_content_type(signer: &SignerInfo, content_type: &str, report: &mut VerificationReport, prefix: &str) {
    let name = format!("{prefix}: contentType");
    let Some(attribute) = signer.find_signed(oids::CONTENT_TYPE) else {
        report.fail(&name, "the attribute is missing");
        return;
    };
    let found = attribute
        .value()
        .ok_or(DerError::Truncated)
        .and_then(Asn1Node::parse)
        .and_then(|node| node.to_oid());
    match found {
        Ok(found) if found == content_type => {}
        Ok(found) => report.fail(&name, &format!("{found} instead of {content_type}")),
        Err(error) => report.fail(&name, &error.to_string()),
    }
}

// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber, issuerUID OPTIONAL }; the issuer is directoryName [4].
fn issuer_serial_matches(issuer_serial: &[u8], certificate: &Certificate) -> bool {
    let matches = || -> Result<bool, DerError> {
        let node = Asn1Node::parse(issuer_serial)?;
        let fields = if node.has_tag(tag::SEQUENCE) {
            node.children()?
        } else {
            Vec::new()
        };
        if fields.len() < ISSUER_SERIAL_MIN_FIELDS || &fields[1].to_integer()? != certificate.serial_number() {
            return Ok(false);
        }
        for name in fields[0].children()? {
            if name.is_context(DIRECTORY_NAME_TAG)
                && &DistinguishedName::from_asn1(&name.child(0)?)? == certificate.issuer()
            {
                return Ok(true);
            }
        }
        Ok(false)
    };
    matches().is_ok_and(|is_match| is_match)
}

fn octet_string_value(value: Option<&[u8]>) -> Result<Vec<u8>, DerError> {
    Asn1Node::parse(value.ok_or(DerError::Truncated)?)?.to_octet_string()
}

// The DKE of the certificate's key; none when there is no usable DSTU 4145 key.
fn certificate_dke(certificate: &Certificate) -> Option<Vec<u8>> {
    certificate
        .public_key()
        .ok()
        .and_then(|key| key.dke().map(<[u8]>::to_vec))
}
