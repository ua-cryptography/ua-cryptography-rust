//! Verifying a signed file of any supported format and summarizing every check, as `ua-sign verify` does.

use time::OffsetDateTime;
use ua_pki::{CheckStatus, SignedFile, ValidationOptions, VerificationReport, VerificationResult, signature_verifier};

use crate::errors::OperationFailure;
use crate::models::VerificationRequest;
use crate::models::reports::{CheckOutcome, CheckRow, ReferenceRow, SignatureSummary, VerificationSummary};
use crate::operations::certificate_details::describe_certificate;
use crate::operations::service_clients::ServiceClients;
use crate::operations::signing::parse_certificates;
use crate::utils::{describe_hash, describe_signature_algorithm, format_hex, format_time};

/// The verdict on the request's signature at `now`; an invalid signature is a summary, not a failure.
pub fn verify(request: &VerificationRequest, now: OffsetDateTime) -> Result<VerificationSummary, OperationFailure> {
    let clients = ServiceClients::connect(None, request.is_online, None)?;
    let options = ValidationOptions {
        trust_anchors: parse_certificates(&request.trust_anchors)?,
        extra_certificates: parse_certificates(&request.certificates)?,
        online_ocsp: clients.ocsp(),
        downloads: clients.downloads(),
        current_time: Some(now),
    };
    let resolve = |name: Option<&str>| find_detached_data(&request.data, name);
    let result = signature_verifier::verify(&request.signature, &resolve, &options)?;
    Ok(summarize(&result, now))
}

// A XAdES reference by its file name; one file stands for whatever the signature asks, a detached CAdES included.
fn find_detached_data(data: &[SignedFile], name: Option<&str>) -> Option<Vec<u8>> {
    let given = name.and_then(|name| {
        let base_name = base_name_of(name);
        data.iter().find(|file| base_name_of(&file.name) == base_name)
    });
    match (given, data) {
        (Some(file), _) => Some(file.content.clone()),
        (None, [single]) => Some(single.content.clone()),
        (None, _) => None,
    }
}

// "dir/doc.txt" and "dir\doc.txt" name "doc.txt".
fn base_name_of(name: &str) -> &str {
    match name.rsplit(['/', '\\']).next() {
        Some(base_name) => base_name,
        None => name,
    }
}

fn summarize(result: &VerificationResult, now: OffsetDateTime) -> VerificationSummary {
    VerificationSummary {
        format: result.format.clone(),
        is_valid: result.is_valid(),
        signature_count: result
            .signatures
            .iter()
            .filter(|report| report.title != signature_verifier::CONTAINER_TITLE)
            .count(),
        warning_count: count_checks(&result.signatures, CheckStatus::Warning),
        failure_count: count_checks(&result.signatures, CheckStatus::Failed),
        verified_at: format_time(now),
        signed_files: result.signed_files.iter().map(|file| file.name.clone()).collect(),
        signatures: result
            .signatures
            .iter()
            .map(|report| summarize_report(report, now))
            .collect(),
    }
}

fn summarize_report(report: &VerificationReport, now: OffsetDateTime) -> SignatureSummary {
    SignatureSummary {
        title: report.title.clone(),
        level: report.level.clone(),
        packaging: report.packaging.clone(),
        signature_algorithm: report.signature_algorithm.as_deref().map(describe_signature_algorithm),
        digest_algorithm: report.digest_algorithm.as_deref().map(describe_hash),
        signing_time: report.claimed_signing_time.map(format_time),
        timestamp_time: report.time_stamp_time.map(format_time),
        validation_time: report.signer.as_ref().map(|_| format_time(report.validation_time(now))),
        is_valid: report.is_valid(),
        has_warnings: report.has_warnings(),
        signer: report.signer.as_ref().map(describe_certificate),
        references: report
            .signed_objects
            .iter()
            .map(|signed| ReferenceRow {
                name: signed.name.clone(),
                digest_algorithm: describe_hash(&signed.hash_algorithm),
                digest: format_hex(&signed.digest),
            })
            .collect(),
        checks: report
            .checks
            .iter()
            .map(|check| CheckRow {
                name: check.name.clone(),
                status: outcome_of(check.status),
                details: check.details.clone(),
            })
            .collect(),
    }
}

fn outcome_of(status: CheckStatus) -> CheckOutcome {
    match status {
        CheckStatus::Passed => CheckOutcome::Passed,
        CheckStatus::Warning => CheckOutcome::Warning,
        CheckStatus::Failed => CheckOutcome::Failed,
    }
}

fn count_checks(reports: &[VerificationReport], status: CheckStatus) -> usize {
    reports
        .iter()
        .flat_map(|report| &report.checks)
        .filter(|check| check.status == status)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::simple_types::{SignatureFormat, SignatureHash};
    use crate::models::{KeyStoreRequest, SigningOptions, SigningRequest};
    use crate::operations::{key_store, signing};
    use ua_pki::SignatureLevel;

    const PASSWORD: &str = "password";

    fn sign_files(format: SignatureFormat, files: Vec<SignedFile>, is_detached: bool) -> (Vec<u8>, Vec<u8>) {
        let request = KeyStoreRequest {
            subject: "CN=Signer,O=Organization,C=UA".to_owned(),
            alias: "key".to_owned(),
            m: 257,
            validity_days: 30,
            signature_hash: SignatureHash::Dstu7564,
            password: PASSWORD.to_owned(),
        };
        let created = key_store::create_key_store(&request, OffsetDateTime::now_utc()).unwrap();
        let signature = signing::sign(&SigningRequest {
            key_store: created.key_store,
            password: PASSWORD.to_owned(),
            alias: None,
            files,
            certificates: Vec::new(),
            options: SigningOptions {
                format,
                level: SignatureLevel::B,
                hash: SignatureHash::Dstu7564,
                is_detached,
                has_content_time_stamp: false,
                tsa_url: None,
                ocsp_url: None,
            },
        })
        .unwrap();
        (signature, created.certificate)
    }

    fn file(name: &str, content: &[u8]) -> SignedFile {
        SignedFile {
            name: name.to_owned(),
            content: content.to_vec(),
        }
    }

    fn verify_offline(signature: Vec<u8>, data: Vec<SignedFile>, trust: Vec<u8>) -> VerificationSummary {
        let request = VerificationRequest {
            signature,
            data,
            trust_anchors: vec![trust],
            certificates: Vec::new(),
            is_online: false,
        };
        verify(&request, OffsetDateTime::now_utc()).unwrap()
    }

    #[test]
    fn every_format_signed_here_verifies() {
        for format in [
            SignatureFormat::Cades,
            SignatureFormat::AsicS,
            SignatureFormat::Xades,
            SignatureFormat::AsicE,
        ] {
            let data = vec![file("document.txt", b"document")];
            let (signature, certificate) = sign_files(format, data.clone(), false);
            let summary = verify_offline(signature, data, certificate);
            assert!(summary.is_valid, "{format:?}: {summary:#?}");
            assert_eq!(summary.signature_count, 1);
        }
    }

    #[test]
    fn a_detached_signature_over_other_data_is_invalid() {
        let (signature, certificate) = sign_files(SignatureFormat::Cades, vec![file("a.txt", b"original")], true);
        let summary = verify_offline(signature, vec![file("a.txt", b"tampered")], certificate);
        assert!(!summary.is_valid);
        assert!(summary.failure_count > 0);
    }

    #[test]
    fn a_reference_finds_its_file_by_name() {
        let data = [file("a.txt", b"a"), file("dir/b.txt", b"b")];
        assert_eq!(find_detached_data(&data, Some("b.txt")), Some(b"b".to_vec()));
        assert_eq!(find_detached_data(&data, Some("c.txt")), None);
        assert_eq!(find_detached_data(&data[..1], None), Some(b"a".to_vec()));
    }
}
