//! Certification paths: the real "Дія" CA up to a ЦЗО root, the synthetic hierarchy with OCSP, and the ways a path
//! can fail (untrusted root, expiry, a CA that is not a CA, an impostor with the issuer's name, a missing or
//! unauthorized responder).

mod common;

use common::{Hierarchy, TestOcsp, czo_roots, has_check, read_json, read_oracle, real_certificate, respond};
use time::{Duration, OffsetDateTime};
use ua_pki::{
    Certificate, CertificateBuilder, CheckStatus, DistinguishedName, Dstu4145PrivateKey, OcspCertificateStatus,
    OcspResponse, ValidationOptions, VerificationReport, certificate_path_validator,
};

fn validate(
    leaf: &Certificate,
    pool: &[Certificate],
    ocsp: &[OcspResponse],
    options: &ValidationOptions<'_>,
    time: OffsetDateTime,
) -> VerificationReport {
    let mut report = VerificationReport::new("test");
    certificate_path_validator::validate(leaf, pool, ocsp, options, time, &mut report, "path");
    report
}

fn trusting_root() -> ValidationOptions<'static> {
    ValidationOptions {
        trust_anchors: vec![Hierarchy::shared().root.certificate.clone()],
        ..ValidationOptions::default()
    }
}

#[test]
fn the_diia_ca_chains_to_the_trusted_czo_root() {
    let diia = real_certificate("intermediates/dia-knedp.cer");
    let time = diia.not_before() + Duration::days(1);
    let options = ValidationOptions {
        trust_anchors: czo_roots(),
        ..ValidationOptions::default()
    };
    let report = validate(&diia, &[], &[], &options, time);
    assert!(report.is_valid(), "{:?}", report.checks);
    assert!(has_check(&report, "path: trust", CheckStatus::Passed));

    // Without the roots the path stops at the CA itself.
    let report = validate(&diia, &[], &[], &ValidationOptions::default(), time);
    assert!(has_check(&report, "path: trust", CheckStatus::Warning));
}

#[test]
fn the_synthetic_signer_with_ocsp_is_fully_validated() {
    let pki = Hierarchy::shared();
    let signer = &pki.signer.certificate;
    let ca = &pki.issuing_ca.certificate;
    let root = &pki.root.certificate;
    let rust_made = vec![
        OcspResponse::load(&respond(&pki.ocsp, signer, ca, false)).unwrap(),
        OcspResponse::load(&respond(&pki.root_ocsp, ca, root, false)).unwrap(),
    ];
    let recorded = vec![
        OcspResponse::load(&read_oracle("hierarchy/ocsp-signer.der")).unwrap(),
        OcspResponse::load(&read_oracle("hierarchy/ocsp-issuing-ca.der")).unwrap(),
    ];
    let now = OffsetDateTime::now_utc();
    for responses in [rust_made, recorded] {
        let report = validate(signer, std::slice::from_ref(ca), &responses, &trusting_root(), now);
        assert!(report.is_valid(), "{:?}", report.checks);
        assert!(
            report.checks.iter().all(|check| check.status == CheckStatus::Passed),
            "{:?}",
            report.checks
        );
        let revocation_checks = report
            .checks
            .iter()
            .filter(|check| check.name.starts_with("path: revocation"))
            .count();
        assert_eq!(revocation_checks, 2);
        assert_eq!(report.paths[0].certificates, [signer.clone(), ca.clone(), root.clone()]);
        let revoked: Vec<&Certificate> = report.revocations.iter().map(|status| &status.certificate).collect();
        assert_eq!(revoked, [signer, ca]);
        assert!(
            report
                .revocations
                .iter()
                .all(|status| status.status.status == OcspCertificateStatus::Good)
        );
        assert!(report.revocations.iter().all(|status| !status.is_online));

        // A response about another certificate does not count.
        let report = validate(signer, std::slice::from_ref(ca), &responses[1..], &trusting_root(), now);
        assert!(has_check(
            &report,
            "path: revocation of 'Test Signer'",
            CheckStatus::Warning
        ));
    }

    // The same path asked online instead of from embedded responses.
    let online = TestOcsp::new();
    let options = ValidationOptions {
        online_ocsp: Some(&online),
        ..trusting_root()
    };
    let report = validate(signer, std::slice::from_ref(ca), &[], &options, now);
    assert!(report.is_valid(), "{:?}", report.checks);
    assert_eq!(online.requests.get(), 2);
    assert!(report.revocations.iter().all(|status| status.is_online));
}

#[test]
fn failures_are_reported() {
    let pki = Hierarchy::shared();
    let signer = &pki.signer.certificate;
    let ca = &pki.issuing_ca.certificate;
    let root = &pki.root.certificate;
    let now = OffsetDateTime::now_utc();

    // Untrusted: the synthetic root is not a ЦЗО root.
    let czo = ValidationOptions {
        trust_anchors: czo_roots(),
        ..ValidationOptions::default()
    };
    let report = validate(signer, &[ca.clone(), root.clone()], &[], &czo, now);
    assert!(has_check(&report, "path: trust", CheckStatus::Failed));

    // Expired at the validation time.
    let report = validate(
        signer,
        std::slice::from_ref(ca),
        &[],
        &trusting_root(),
        signer.not_after() + Duration::days(1),
    );
    assert!(has_check(
        &report,
        "path: validity of 'Test Signer'",
        CheckStatus::Failed
    ));

    // An impostor root with the same name does not verify the CA, so the path is incomplete.
    let impostor_key = Dstu4145PrivateKey::generate(root.public_key().unwrap().domain());
    let impostor = CertificateBuilder::new(root.subject().clone(), impostor_key.public_key().clone())
        .unwrap()
        .add_basic_constraints(true)
        .self_sign(&impostor_key)
        .unwrap();
    let options = ValidationOptions {
        trust_anchors: vec![impostor],
        ..ValidationOptions::default()
    };
    let report = validate(signer, std::slice::from_ref(ca), &[], &options, now);
    assert!(has_check(&report, "path: trust", CheckStatus::Failed));

    // A certificate that issues another one without being a CA.
    let leaf_key = Dstu4145PrivateKey::generate(root.public_key().unwrap().domain());
    let leaf = CertificateBuilder::new(
        DistinguishedName::parse("CN=Below a leaf").unwrap(),
        leaf_key.public_key().clone(),
    )
    .unwrap()
    .issue(signer, &pki.signer.key)
    .unwrap();
    let report = validate(&leaf, &[signer.clone(), ca.clone()], &[], &trusting_root(), now);
    assert!(has_check(&report, "path: 'Test Signer'", CheckStatus::Failed));
}

#[test]
fn ocsp_with_a_zero_issuer_key_hash_is_matched_by_name_and_serial() {
    // The "Дія" responder fills the CertID issuerKeyHash with zeros.
    let pki = Hierarchy::shared();
    let signer = &pki.signer.certificate;
    let ca = &pki.issuing_ca.certificate;
    let root = &pki.root.certificate;
    let now = OffsetDateTime::now_utc();
    let rust_made = OcspResponse::load(&respond(&pki.ocsp, signer, ca, true)).unwrap();
    let recorded = OcspResponse::load(&read_oracle("ocsp/signer-zero-key-hash.der")).unwrap();
    for zero in [rust_made, recorded] {
        assert!(zero.responses()[0].issuer_key_hash.iter().all(|&byte| byte == 0));
        let report = validate(
            signer,
            std::slice::from_ref(ca),
            std::slice::from_ref(&zero),
            &trusting_root(),
            now,
        );
        assert!(has_check(
            &report,
            "path: revocation of 'Test Signer'",
            CheckStatus::Passed
        ));

        // The name hash and the serial number still have to match.
        assert!(zero.find(signer, ca).is_some());
        assert!(zero.find(signer, root).is_none());
        assert!(zero.find(ca, ca).is_none());
    }

    // And the responder still has to be authorized by the issuer.
    let rust_made = OcspResponse::load(&respond(&pki.root_ocsp, signer, ca, true)).unwrap();
    let recorded = OcspResponse::load(&read_oracle("ocsp/signer-by-root-responder-zero-key-hash.der")).unwrap();
    for foreign in [rust_made, recorded] {
        let report = validate(signer, std::slice::from_ref(ca), &[foreign], &trusting_root(), now);
        assert!(has_check(
            &report,
            "path: revocation of 'Test Signer'",
            CheckStatus::Failed
        ));
    }
}

#[test]
fn ocsp_from_an_unauthorized_responder_is_refused() {
    // The root's responder answers about the signer, whose issuer is the issuing CA: not its responder.
    let pki = Hierarchy::shared();
    let signer = &pki.signer.certificate;
    let ca = &pki.issuing_ca.certificate;
    let rust_made = OcspResponse::load(&respond(&pki.root_ocsp, signer, ca, false)).unwrap();
    let recorded = OcspResponse::load(&read_oracle("ocsp/signer-by-root-responder.der")).unwrap();
    for foreign in [rust_made, recorded] {
        let report = validate(
            signer,
            std::slice::from_ref(ca),
            &[foreign],
            &trusting_root(),
            OffsetDateTime::now_utc(),
        );
        assert!(has_check(
            &report,
            "path: revocation of 'Test Signer'",
            CheckStatus::Failed
        ));
    }
}

#[test]
fn every_recorded_response_about_the_signer_gets_the_csharp_status() {
    let pki = Hierarchy::shared();
    for expected in read_json("ocsp/ocsp.json")["responses"].as_array().unwrap() {
        let Some(check) = expected.get("pathRevocationCheck") else {
            continue;
        };
        let response = OcspResponse::load(&read_oracle(expected["file"].as_str().unwrap())).unwrap();
        let report = validate(
            &pki.signer.certificate,
            std::slice::from_ref(&pki.issuing_ca.certificate),
            &[response],
            &trusting_root(),
            OffsetDateTime::now_utc(),
        );
        let status = match check["status"].as_str().unwrap() {
            "Passed" => CheckStatus::Passed,
            "Warning" => CheckStatus::Warning,
            _ => CheckStatus::Failed,
        };
        assert!(
            has_check(&report, check["name"].as_str().unwrap(), status),
            "{}",
            expected["file"]
        );
    }
}
