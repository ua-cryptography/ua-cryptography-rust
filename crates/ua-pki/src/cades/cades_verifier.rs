//! Verifies CAdES signatures (docs/signature-formats.md, section 9): for every signer the binding to the data and
//! to the certificate, the DSTU 4145 signature, the time-stamps, the long-term validation values and the
//! certificate path.

use time::OffsetDateTime;
use ua_der::{Asn1Node, DerError, tag};

use crate::algorithms;
use crate::cms::{SignedData, SignerInfo, cms_verifier};
use crate::errors::VerificationError;
use crate::ocsp::OcspResponse;
use crate::oids;
use crate::tsp::TimeStampToken;
use crate::validation::{
    CheckStatus, SignedObject, TimeStampDetails, ValidationOptions, VerificationReport, VerificationResult,
    certificate_path_validator,
};
use crate::x509::Certificate;
use crate::xades::SignedFile;

/// The name of the encapsulated or detached content among the signed files.
pub const CONTENT_NAME: &str = "content";
/// The context tag of RevocationValues.ocspVals and of CrlOcspRef.ocspids.
const OCSP_TAG: u8 = 1;
/// The check name of the signature time-stamp.
const SIGNATURE_TIME_STAMP: &str = "signature time-stamp";
/// The check name of the content time-stamp.
const CONTENT_TIME_STAMP: &str = "content time-stamp";

/// Verifies a .p7s (DER, PEM or base64); `detached_content` is the data of a detached signature.
pub fn verify(
    signature: &[u8],
    detached_content: Option<&[u8]>,
    options: &ValidationOptions<'_>,
) -> Result<VerificationResult, VerificationError> {
    let cms = SignedData::load(signature)?;
    let content = cms.content().or(detached_content);
    let signer_count = cms.signer_infos().len();
    let mut reports = Vec::new();
    for (index, signer) in cms.signer_infos().iter().enumerate() {
        let title = if signer_count == 1 {
            "CAdES signature".to_owned()
        } else {
            format!("CAdES signature {}", index + 1)
        };
        reports.push(verify_signer(&cms, signer, content, options, &title)?);
    }
    let signed_files = match content {
        Some(content) => vec![SignedFile {
            name: CONTENT_NAME.to_owned(),
            content: content.to_vec(),
        }],
        None => Vec::new(),
    };
    let format = if cms.content().is_none() {
        "CAdES (detached)"
    } else {
        "CAdES (enveloped)"
    };
    Ok(VerificationResult {
        format: format.to_owned(),
        signatures: reports,
        signed_files,
    })
}

fn verify_signer(
    cms: &SignedData,
    signer: &SignerInfo,
    content: Option<&[u8]>,
    options: &ValidationOptions<'_>,
    title: &str,
) -> Result<VerificationReport, VerificationError> {
    let mut report = VerificationReport::new(title);
    let certificate_values = read_certificate_values(signer)?;
    let ocsp_values = read_revocation_values(signer)?;
    let known: Vec<Certificate> = cms
        .certificates()
        .iter()
        .chain(&certificate_values)
        .chain(&options.extra_certificates)
        .cloned()
        .collect();

    let certificate = cms.find_certificate(signer, &known);
    describe_format(
        cms,
        signer,
        !certificate_values.is_empty() || !ocsp_values.is_empty(),
        &mut report,
    );
    let Some(certificate) = certificate else {
        report.fail(
            "signer certificate",
            &format!("the certificate ({signer}) is not in the signature and was not given"),
        );
        return Ok(report);
    };
    report.signer = Some(certificate.clone());
    let Some(content) = content else {
        report.fail("content", "the signature is detached and the signed data was not given");
        return Ok(report);
    };

    cms_verifier::verify_signer(signer, &certificate, cms.content_type(), content, &mut report, "CMS");
    if let Some(time) = signer.find_signed(oids::SIGNING_TIME) {
        report.claimed_signing_time = time.value().and_then(|value| read_time(value).ok());
    }

    let pool = verify_time_stamps(signer, content, &certificate, &known, options, &mut report);

    if signer.find_unsigned(oids::CERTIFICATE_REFS).is_some() || signer.find_unsigned(oids::REVOCATION_REFS).is_some() {
        check_references(signer, &certificate_values, &ocsp_values, &mut report);
    }

    let path_pool: Vec<Certificate> = known.iter().chain(&pool).cloned().collect();
    let time = report.validation_time(options.now());
    certificate_path_validator::validate(
        &certificate,
        &path_pool,
        &ocsp_values,
        options,
        time,
        &mut report,
        "signer",
    );
    Ok(report)
}

// contentTimeStamp over the data, signatureTimeStampToken over the signature value; returns the certificates known
// after them (those of the tokens and of caIssuers downloads added).
fn verify_time_stamps(
    signer: &SignerInfo,
    content: &[u8],
    certificate: &Certificate,
    known: &[Certificate],
    options: &ValidationOptions<'_>,
    report: &mut VerificationReport,
) -> Vec<Certificate> {
    let mut pool = known.to_vec();
    let content_stamp = signer
        .find_signed(oids::CONTENT_TIME_STAMP)
        .and_then(|attribute| attribute.value());
    if let Some(value) = content_stamp {
        let stamp = TimeStampCheck {
            value,
            covered: content,
            signer_certificate: certificate,
            name: CONTENT_TIME_STAMP,
        };
        verify_time_stamp(&stamp, &mut pool, options, report);
    }
    let signature_stamp = signer
        .find_unsigned(oids::SIGNATURE_TIME_STAMP_TOKEN)
        .and_then(|attribute| attribute.value());
    if let Some(value) = signature_stamp {
        let stamp = TimeStampCheck {
            value,
            covered: signer.signature(),
            signer_certificate: certificate,
            name: SIGNATURE_TIME_STAMP,
        };
        let token = verify_time_stamp(&stamp, &mut pool, options, report);
        let has_failure = report
            .checks
            .iter()
            .any(|check| check.name.starts_with(SIGNATURE_TIME_STAMP) && check.status == CheckStatus::Failed);
        if let Some(token) = token.filter(|_| !has_failure) {
            report.time_stamp_time = Some(token.gen_time());
        }
    }
    pool
}

fn describe_format(cms: &SignedData, signer: &SignerInfo, is_long_term: bool, report: &mut VerificationReport) {
    let has_time_stamp = signer.find_unsigned(oids::SIGNATURE_TIME_STAMP_TOKEN).is_some();
    let level = if is_long_term {
        "CAdES-X Long"
    } else if has_time_stamp {
        "CAdES-T"
    } else {
        "CAdES-B"
    };
    let packaging = if cms.content().is_none() {
        "detached"
    } else {
        "enveloped"
    };
    report.format = Some(format!(
        "{level}, {packaging}, {}",
        algorithms::hash_name(signer.digest_algorithm())
    ));
    report.level = Some(level.to_owned());
    report.packaging = Some(packaging.to_owned());
    report.signature_algorithm = Some(signer.signature_algorithm().to_owned());
    report.digest_algorithm = Some(signer.digest_algorithm().to_owned());
    let digest = signer
        .find_signed(oids::MESSAGE_DIGEST)
        .and_then(|attribute| attribute.value());
    if let Some(digest) = digest.and_then(|value| Asn1Node::parse(value).and_then(|node| node.to_octet_string()).ok()) {
        report.signed_objects.push(SignedObject {
            name: CONTENT_NAME.to_owned(),
            hash_algorithm: signer.digest_algorithm().to_owned(),
            digest,
        });
    }
}

/// A time-stamp attribute to verify.
struct TimeStampCheck<'a> {
    value: &'a [u8],
    covered: &'a [u8],
    signer_certificate: &'a Certificate,
    name: &'a str,
}

// Returns the token only when the service's certificate was found and checked. A token without that certificate is
// completed, when downloads are allowed, from the caIssuers addresses of the signer's certificate.
fn verify_time_stamp(
    stamp: &TimeStampCheck<'_>,
    pool: &mut Vec<Certificate>,
    options: &ValidationOptions<'_>,
    report: &mut VerificationReport,
) -> Option<TimeStampToken> {
    let token = match TimeStampToken::load(stamp.value) {
        Ok(token) => token,
        Err(error) => {
            report.fail(stamp.name, &error.to_string());
            return None;
        }
    };
    if let Some(downloads) = options.downloads {
        if token.find_signer_certificate(pool).is_none() {
            pool.extend(certificate_path_validator::download_issuers(
                stamp.signer_certificate,
                downloads,
            ));
        }
    }
    let authority = token.verify(stamp.covered, pool, report, stamp.name);
    report.time_stamps.push(TimeStampDetails {
        kind: stamp.name.to_owned(),
        token: token.clone(),
        authority: authority.clone(),
    });
    let authority = authority?;
    pool.extend(token.cms().certificates().iter().cloned());
    let name = format!("{} service", stamp.name);
    certificate_path_validator::validate(&authority, pool, &[], options, token.gen_time(), report, &name);
    Some(token)
}

fn read_certificate_values(signer: &SignerInfo) -> Result<Vec<Certificate>, VerificationError> {
    let Some(value) = signer
        .find_unsigned(oids::CERT_VALUES)
        .and_then(|attribute| attribute.value())
    else {
        return Ok(Vec::new());
    };
    let mut certificates = Vec::new();
    for certificate in Asn1Node::parse(value)?.children()? {
        certificates.push(Certificate::load(certificate.encoded())?);
    }
    Ok(certificates)
}

// RevocationValues ::= SEQUENCE { crlVals [0] OPTIONAL, ocspVals [1] EXPLICIT SEQUENCE OF BasicOCSPResponse, ... }
fn read_revocation_values(signer: &SignerInfo) -> Result<Vec<OcspResponse>, VerificationError> {
    let Some(value) = signer
        .find_unsigned(oids::REVOCATION_VALUES)
        .and_then(|attribute| attribute.value())
    else {
        return Ok(Vec::new());
    };
    let values = Asn1Node::parse(value)?.children()?;
    let Some(ocsp) = values.iter().find(|node| node.is_context(OCSP_TAG)) else {
        return Ok(Vec::new());
    };
    let mut responses = Vec::new();
    for response in ocsp.child(0)?.children()? {
        responses.push(OcspResponse::load_basic(response.encoded())?);
    }
    Ok(responses)
}

// Every complete certificate / revocation reference has a value with the same hash (CAdES-C ↔ CAdES-X Long).
fn check_references(
    signer: &SignerInfo,
    certificate_values: &[Certificate],
    ocsp_values: &[OcspResponse],
    report: &mut VerificationReport,
) {
    if let Some(value) = signer
        .find_unsigned(oids::CERTIFICATE_REFS)
        .and_then(|attribute| attribute.value())
    {
        let name = "certificate references";
        match count_missing_certificates(value, certificate_values) {
            Ok((0, total)) => report.pass(name, &format!("{total} references match certValues")),
            Ok((missing, _)) => report.fail(name, &format!("{missing} references have no matching certificate")),
            Err(error) => report.fail(name, &error.to_string()),
        }
    }
    if let Some(value) = signer
        .find_unsigned(oids::REVOCATION_REFS)
        .and_then(|attribute| attribute.value())
    {
        let name = "revocation references";
        match count_missing_responses(value, ocsp_values) {
            Ok((0, total)) => report.pass(name, &format!("{total} OCSP references match revocationValues")),
            Ok((missing, _)) => report.fail(name, &format!("{missing} OCSP references have no matching response")),
            Err(error) => report.fail(name, &error.to_string()),
        }
    }
}

// CompleteCertificateRefs ::= SEQUENCE OF OtherCertID { otherCertHash, issuerSerial OPTIONAL }: (missing, total).
fn count_missing_certificates(value: &[u8], certificates: &[Certificate]) -> Result<(usize, usize), DerError> {
    let references = Asn1Node::parse(value)?.children()?;
    let mut missing = 0;
    for reference in &references {
        let hash = reference.child(0)?;
        if !certificates
            .iter()
            .any(|certificate| hash_matches(&hash, certificate.encoded()))
        {
            missing += 1;
        }
    }
    Ok((missing, references.len()))
}

// Only identifiers with an ocspRepHash can be matched: (missing, total).
fn count_missing_responses(value: &[u8], responses: &[OcspResponse]) -> Result<(usize, usize), DerError> {
    let identifiers = read_ocsp_identifiers(value)?;
    let mut missing = 0;
    for identifier in &identifiers {
        let Ok(hash) = identifier.child(1) else {
            continue;
        };
        if !responses
            .iter()
            .any(|response| hash_matches(&hash, response.basic_encoded()))
        {
            missing += 1;
        }
    }
    Ok((missing, identifiers.len()))
}

// CrlOcspRef ::= SEQUENCE { crlids [0], ocspids [1] EXPLICIT OcspListID, otherRev [2] }
// OcspListID ::= SEQUENCE { ocspResponses SEQUENCE OF OcspResponsesID { ocspIdentifier, ocspRepHash OPTIONAL } }
fn read_ocsp_identifiers(value: &[u8]) -> Result<Vec<Asn1Node<'_>>, DerError> {
    let mut identifiers = Vec::new();
    for reference in Asn1Node::parse(value)?.children()? {
        for ocsp in reference.children()?.iter().filter(|node| node.is_context(OCSP_TAG)) {
            identifiers.extend(ocsp.child(0)?.child(0)?.children()?);
        }
    }
    Ok(identifiers)
}

// OtherHash ::= CHOICE { sha1Hash OCTET STRING, otherHash SEQUENCE { hashAlgorithm, hashValue } }
fn hash_matches(other_hash: &Asn1Node<'_>, encoded: &[u8]) -> bool {
    let read = || -> Result<(String, Vec<u8>), DerError> {
        if other_hash.has_tag(tag::OCTET_STRING) {
            return Ok((oids::SHA1.to_owned(), other_hash.to_octet_string()?));
        }
        Ok((
            other_hash.child(0)?.child(0)?.to_oid()?,
            other_hash.child(1)?.to_octet_string()?,
        ))
    };
    let Ok((oid, value)) = read() else {
        return false;
    };
    algorithms::is_supported_hash(&oid) && algorithms::hash(&oid, encoded, None).is_ok_and(|hash| hash == value)
}

fn read_time(value: &[u8]) -> Result<OffsetDateTime, DerError> {
    Asn1Node::parse(value)?.to_time()
}
