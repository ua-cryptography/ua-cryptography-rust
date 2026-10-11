//! Every signature of `testdata/oracle/pki/manifest.json` — made by the C# package, by the C# test builders and as
//! the providers make them — verified by the Rust verifier with the options recorded beside it: the same verdict, the
//! same format, the same reports with the same checks in the same order.

mod common;

use std::collections::BTreeMap;

use common::{check_lines, oracle_certificate, read_json, read_oracle};
use ua_cryptography_pki::{
    Certificate, CertificateSource, OcspResponse, OcspService, ServiceError, ValidationOptions, signature_verifier,
};

/// caIssuers downloads answered from the manifest.
struct RecordedDownloads {
    bundles: BTreeMap<String, Vec<Certificate>>,
}

impl CertificateSource for RecordedDownloads {
    fn download_certificates(&self, url: &str) -> Result<Vec<Certificate>, ServiceError> {
        Ok(self.bundles.get(url).cloned().unwrap_or_default())
    }
}

/// OCSP answered from the manifest: the recorded response about each certificate.
struct RecordedOcsp {
    responses: Vec<(Certificate, OcspResponse)>,
}

impl OcspService for RecordedOcsp {
    fn find_response(
        &self,
        certificate: &Certificate,
        _issuer: &Certificate,
        _hash_oid: &str,
    ) -> Result<Option<OcspResponse>, ServiceError> {
        Ok(self
            .responses
            .iter()
            .find(|(known, _)| known == certificate)
            .map(|(_, response)| response.clone()))
    }
}

fn certificates(files: &serde_json::Value) -> Vec<Certificate> {
    files
        .as_array()
        .unwrap()
        .iter()
        .map(|file| oracle_certificate(file.as_str().unwrap()))
        .collect()
}

#[test]
fn the_rust_verifier_gives_every_fixture_the_csharp_verdict_and_checks() {
    let manifest = read_json("manifest.json");
    let signatures = manifest["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 66);
    let mut verified = 0;
    for entry in signatures {
        let file = entry["file"].as_str().unwrap();
        let signature = read_oracle(file);
        let data: Vec<(String, Vec<u8>)> = entry["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["name"].as_str().unwrap().to_owned(),
                    read_oracle(item["file"].as_str().unwrap()),
                )
            })
            .collect();
        let detached = |name: Option<&str>| -> Option<Vec<u8>> {
            match name {
                None if data.len() == 1 => Some(data[0].1.clone()),
                None => None,
                Some(name) => data
                    .iter()
                    .find(|(known, _)| known == name)
                    .map(|(_, content)| content.clone()),
            }
        };
        for verification in entry["verifications"].as_array().unwrap() {
            let downloads = RecordedDownloads {
                bundles: verification["downloads"]
                    .as_object()
                    .map(|bundles| {
                        bundles
                            .iter()
                            .map(|(url, files)| (url.clone(), certificates(files)))
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            let ocsp = RecordedOcsp {
                responses: verification["onlineOcsp"]
                    .as_object()
                    .map(|responses| {
                        responses
                            .iter()
                            .map(|(certificate, response)| {
                                let response = OcspResponse::load(&read_oracle(response.as_str().unwrap())).unwrap();
                                (oracle_certificate(certificate), response)
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            let options = ValidationOptions {
                trust_anchors: certificates(&verification["trustAnchors"]),
                extra_certificates: certificates(&verification["extraCertificates"]),
                downloads: verification["downloads"]
                    .is_object()
                    .then_some(&downloads as &dyn CertificateSource),
                online_ocsp: verification["onlineOcsp"]
                    .is_object()
                    .then_some(&ocsp as &dyn OcspService),
                current_time: None,
            };
            let result = signature_verifier::verify(&signature, &detached, &options).unwrap();
            assert_eq!(result.is_valid(), verification["valid"].as_bool().unwrap(), "{file}");
            assert_eq!(result.format, verification["format"].as_str().unwrap(), "{file}");
            let expected_reports = verification["reports"].as_array().unwrap();
            assert_eq!(result.signatures.len(), expected_reports.len(), "{file}");
            for (report, expected) in result.signatures.iter().zip(expected_reports) {
                assert_eq!(report.title, expected["title"].as_str().unwrap(), "{file}");
                assert_eq!(
                    report.format.as_deref(),
                    expected["format"].as_str(),
                    "{file}: {}",
                    report.title
                );
                assert_eq!(
                    report.is_valid(),
                    expected["valid"].as_bool().unwrap(),
                    "{file}: {}",
                    report.title
                );
                let expected_checks: Vec<&str> = expected["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|check| check.as_str().unwrap())
                    .collect();
                assert_eq!(check_lines(report), expected_checks, "{file}: {}", report.title);
            }
            for required in verification["requiredChecks"].as_array().unwrap() {
                let line = format!(
                    "{}: {}",
                    required["status"].as_str().unwrap(),
                    required["name"].as_str().unwrap()
                );
                let lines: Vec<String> = result.signatures.iter().flat_map(check_lines).collect();
                assert!(lines.contains(&line), "{file}: {line}");
            }
            verified += 1;
        }
    }
    assert!(verified >= 66);
}
