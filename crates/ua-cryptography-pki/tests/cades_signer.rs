//! CAdES made by the crate and checked by the independent recipes, CAdES made by the C# test builder (recorded)
//! checked by the crate's verifier, and negative cases for every check.

mod common;

use std::cell::RefCell;

use common::{Hierarchy, TestOcsp, TestTimeStamps, describe, describe_report, has_check, read_oracle, recipes};
use num_bigint::BigInt;
use ua_cryptography_der::Asn1Node;
use ua_cryptography_pki::{
    CadesOptions, CadesSigner, Certificate, CertificateBuilder, CertificateSource, CheckStatus, KeyUsageFlags,
    ServiceError, SignatureLevel, SignatureServices, SigningError, SigningKey, ValidationOptions, cades_verifier,
    cms_builder, oids,
};

const DATA: &[u8] = "Документ для підпису".as_bytes();

fn variants() -> [(&'static str, bool); 4] {
    [
        (oids::DSTU7564_256, false),
        (oids::DSTU7564_256, true),
        (oids::GOST34311, false),
        (oids::GOST34311, true),
    ]
}

fn sign(options: &CadesOptions) -> Vec<u8> {
    let time_stamps = TestTimeStamps::new();
    let ocsp = TestOcsp::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ocsp: Some(&ocsp),
        ..SignatureServices::default()
    };
    CadesSigner::new(Hierarchy::shared().signing_key(), services)
        .sign(DATA, options)
        .unwrap()
}

fn options(hash_oid: &str, is_detached: bool, level: SignatureLevel) -> CadesOptions {
    CadesOptions {
        hash_oid: hash_oid.to_owned(),
        is_detached,
        level,
        ..CadesOptions::default()
    }
}

#[test]
fn the_crate_signature_verifies_by_the_recipe() {
    let pki = Hierarchy::shared();
    for (hash_oid, is_detached) in variants() {
        let cms = recipes::read_cms(&sign(&options(hash_oid, is_detached, SignatureLevel::B)));
        assert_eq!(cms.signers.len(), 1);
        let signer = &cms.signers[0];
        assert_eq!(signer.digest_algorithm, hash_oid);
        assert_eq!(
            signer.signature_algorithm,
            ua_cryptography_pki::algorithms::signature_algorithm_for(hash_oid).unwrap()
        );
        assert_eq!(cms.content.is_none(), is_detached);

        // messageDigest, signingCertificateV2 and the DSTU 4145 signature, each recomputed by the recipe.
        assert_eq!(signer.message_digest(), recipes::hash(hash_oid, DATA, None));
        assert!(recipes::verify_cms_signer(signer, pki.signer.certificate.encoded()));
        assert!(
            Asn1Node::parse(signer.signed(oids::SIGNING_TIME))
                .unwrap()
                .to_time()
                .is_ok()
        );
        assert_eq!(signer.signature.len(), 64);
    }
}

#[test]
fn the_crate_signature_verifies_by_the_crate() {
    let pki = Hierarchy::shared();
    for (hash_oid, is_detached) in variants() {
        let signature = sign(&options(hash_oid, is_detached, SignatureLevel::B));
        let detached = if is_detached { Some(DATA) } else { None };
        let result = cades_verifier::verify(&signature, detached, &pki.trusting()).unwrap();
        assert!(result.is_valid(), "{}", describe(&result));
        assert_eq!(result.find_signed_file("content"), Some(DATA));
        let report = &result.signatures[0];
        assert_eq!(report.signer.as_ref(), Some(&pki.signer.certificate));
        assert!(has_check(report, "signer: trust", CheckStatus::Passed));
    }
}

#[test]
fn the_test_builder_signatures_verify_by_the_crate() {
    let pki = Hierarchy::shared();
    let data = read_oracle("cades/data.txt");
    let rows = [
        ("cades/cades-dstu7564-enveloped-b.p7s", true, "B", false),
        ("cades/cades-dstu7564-detached-t-content-ts.p7s", false, "T", true),
        ("cades/cades-gost34311-enveloped-t.p7s", true, "T", false),
        ("cades/cades-dstu7564-enveloped-x-long.p7s", true, "X-Long", false),
        (
            "cades/cades-gost34311-detached-x-long-content-ts.p7s",
            false,
            "X-Long",
            true,
        ),
    ];
    for (file, is_enveloped, level, has_content_time_stamp) in rows {
        let detached = if is_enveloped { None } else { Some(data.as_slice()) };
        let result = cades_verifier::verify(&read_oracle(file), detached, &pki.trusting()).unwrap();
        assert!(result.is_valid(), "{file}: {}", describe(&result));
        let report = &result.signatures[0];
        if level != "B" {
            assert!(report.time_stamp_time.is_some(), "{file}");
            assert!(
                has_check(report, "signature time-stamp: imprint", CheckStatus::Passed),
                "{file}"
            );
        }
        if has_content_time_stamp {
            assert!(
                has_check(report, "content time-stamp: imprint", CheckStatus::Passed),
                "{file}"
            );
        }
        let revocations = |status: CheckStatus| {
            report
                .checks
                .iter()
                .filter(|c| c.name.starts_with("signer: revocation") && c.status == status)
                .count()
        };
        if level == "X-Long" {
            assert!(
                has_check(report, "certificate references", CheckStatus::Passed),
                "{file}"
            );
            assert!(
                has_check(report, "revocation references", CheckStatus::Passed),
                "{file}"
            );
            assert_eq!(revocations(CheckStatus::Passed), 2, "{file}");
        } else {
            assert!(revocations(CheckStatus::Warning) > 0, "{file}");
        }
    }
}

#[test]
fn levels_t_and_lt_are_read_by_the_recipe() {
    let pki = Hierarchy::shared();
    for hash_oid in [oids::DSTU7564_256, oids::GOST34311] {
        let mut lt = options(hash_oid, false, SignatureLevel::LT);
        lt.has_content_time_stamp = true;
        let signature = sign(&lt);
        let cms = recipes::read_cms(&signature);
        let signer = &cms.signers[0];

        // Both time-stamps are RFC 3161 tokens signed by the TSA and covering the right bytes.
        let signature_token = signer.unsigned(oids::SIGNATURE_TIME_STAMP_TOKEN);
        assert!(recipes::imprint_covers(signature_token, &signer.signature));
        let token_cms = recipes::read_cms(signature_token);
        assert_eq!(&token_cms.signers[0].serial_number, pki.tsa.certificate.serial_number());
        assert!(recipes::verify_cms_signer(
            &token_cms.signers[0],
            pki.tsa.certificate.encoded()
        ));
        assert!(recipes::imprint_covers(signer.signed(oids::CONTENT_TIME_STAMP), DATA));

        // CAdES-X Long: the references and the values agree.
        let values = Asn1Node::parse(signer.unsigned(oids::CERT_VALUES)).unwrap();
        let certificates: Vec<Vec<u8>> = values
            .children()
            .unwrap()
            .iter()
            .map(|c| c.encoded().to_vec())
            .collect();
        assert!(certificates.contains(&pki.issuing_ca.certificate.encoded().to_vec()));
        assert!(certificates.contains(&pki.root.certificate.encoded().to_vec()));
        for reference in Asn1Node::parse(signer.unsigned(oids::CERTIFICATE_REFS))
            .unwrap()
            .children()
            .unwrap()
        {
            let other_hash = reference.child(0).unwrap();
            let algorithm = other_hash.child(0).unwrap().child(0).unwrap().to_oid().unwrap();
            let value = other_hash.child(1).unwrap().to_octet_string().unwrap();
            assert!(certificates.iter().any(|c| recipes::hash(&algorithm, c, None) == value));
        }
        let revocation_values = Asn1Node::parse(signer.unsigned(oids::REVOCATION_VALUES)).unwrap();
        let ocsp_values = revocation_values
            .child(0)
            .unwrap()
            .child(0)
            .unwrap()
            .children()
            .unwrap();
        assert_eq!(ocsp_values.len(), 2);
        let known: Vec<Vec<u8>> = pki.all_certificates().iter().map(|c| c.encoded().to_vec()).collect();
        for response in &ocsp_values {
            let responder = recipes::find_ocsp_responder(response.encoded(), &known);
            assert!(recipes::verify_ocsp(response.encoded(), &responder));
        }
        let revocation_refs = Asn1Node::parse(signer.unsigned(oids::REVOCATION_REFS)).unwrap();
        let identifiers = revocation_refs
            .child(0)
            .unwrap()
            .child(0)
            .unwrap()
            .child(0)
            .unwrap()
            .child(0)
            .unwrap();
        for identifier in identifiers.children().unwrap() {
            let other_hash = identifier.child(1).unwrap();
            let algorithm = other_hash.child(0).unwrap().child(0).unwrap().to_oid().unwrap();
            let value = other_hash.child(1).unwrap().to_octet_string().unwrap();
            assert!(
                ocsp_values
                    .iter()
                    .any(|r| recipes::hash(&algorithm, r.encoded(), None) == value)
            );
        }

        // And the crate's own verifier finds nothing missing.
        let result = cades_verifier::verify(&signature, None, &pki.trusting()).unwrap();
        assert!(result.is_valid(), "{}", describe(&result));
        let report = &result.signatures[0];
        assert!(
            !report
                .checks
                .iter()
                .any(|c| c.name.starts_with("signer:") && c.status != CheckStatus::Passed)
        );
        assert_eq!(report.level.as_deref(), Some("CAdES-X Long"));
    }
}

#[test]
fn tampered_data_fails_the_message_digest() {
    let signature = sign(&options(oids::DSTU7564_256, true, SignatureLevel::B));
    let mut tampered = DATA.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let result = cades_verifier::verify(&signature, Some(&tampered), &Hierarchy::shared().trusting()).unwrap();
    assert!(!result.is_valid());
    assert!(has_check(
        &result.signatures[0],
        "CMS: messageDigest",
        CheckStatus::Failed
    ));
}

#[test]
fn a_tampered_signature_value_fails() {
    let mut signature = sign(&CadesOptions::default());
    let d = recipes::read_cms(&signature).signers[0].signature.clone();
    let offset = signature.windows(d.len()).position(|window| window == d).unwrap();
    signature[offset + 10] ^= 1;
    let result = cades_verifier::verify(&signature, None, &Hierarchy::shared().trusting()).unwrap();
    assert!(has_check(&result.signatures[0], "CMS: signature", CheckStatus::Failed));
}

#[test]
fn a_foreign_certificate_fails_the_signing_certificate_check() {
    // A second certificate for the same key, issuer and serial number: the signer identifier cannot tell them apart,
    // the signingCertificateV2 hash can.
    let pki = Hierarchy::shared();
    let mut builder = CertificateBuilder::new(
        pki.signer.certificate.subject().clone(),
        pki.signer.key.public_key().clone(),
    )
    .unwrap();
    builder.serial_number = pki.signer.certificate.serial_number().clone();
    let twin = builder.issue(&pki.issuing_ca.certificate, &pki.issuing_ca.key).unwrap();
    let mut twin_chain = vec![twin.clone()];
    twin_chain.extend(pki.signer_chain().into_iter().skip(1));
    let twin_signer = SigningKey::new(pki.signer.key.clone(), twin_chain).unwrap();

    let attributes = cms_builder::signed_attributes(DATA, oids::DATA, &twin_signer, oids::DSTU7564_256, &[]).unwrap();
    let (signer_info, _) = cms_builder::signer_info(&attributes, &twin_signer, oids::DSTU7564_256, &[]).unwrap();
    let honest = cms_builder::signed_data(&signer_info, oids::DSTU7564_256, oids::DATA, Some(DATA), &[twin]);
    let swapped = cms_builder::signed_data(
        &signer_info,
        oids::DSTU7564_256,
        oids::DATA,
        Some(DATA),
        std::slice::from_ref(&pki.signer.certificate),
    );

    assert!(
        cades_verifier::verify(&honest, None, &pki.trusting())
            .unwrap()
            .is_valid()
    );
    let forged = cades_verifier::verify(&swapped, None, &pki.trusting()).unwrap();
    assert!(!forged.is_valid());
    assert!(has_check(
        &forged.signatures[0],
        "CMS: signing certificate",
        CheckStatus::Failed
    ));
}

#[test]
fn signing_certificate_v2_names_the_issuer_and_serial_number() {
    // As IIT and the banks write it: ESSCertIDv2 { hashAlgorithm, certHash, issuerSerial }.
    let pki = Hierarchy::shared();
    let signature = sign(&CadesOptions::default());
    let cms = recipes::read_cms(&signature);
    let attribute = Asn1Node::parse(cms.signers[0].signed(oids::SIGNING_CERTIFICATE_V2)).unwrap();
    let issuer_serial = attribute.child(0).unwrap().child(0).unwrap().child(2).unwrap();
    assert_eq!(
        &issuer_serial.child(1).unwrap().to_integer().unwrap(),
        pki.signer.certificate.serial_number()
    );
    let directory_name = issuer_serial.child(0).unwrap().child(0).unwrap().child(0).unwrap();
    assert_eq!(directory_name.encoded(), pki.issuing_ca.certificate.subject().encoded());

    let result = cades_verifier::verify(&signature, None, &pki.trusting()).unwrap();
    assert!(result.is_valid(), "{}", describe(&result));
    assert!(
        result.signatures[0]
            .checks
            .iter()
            .any(|check| check.name == "CMS: signing certificate"
                && check.details.ends_with("and so do its issuer and serial number"))
    );

    // The right hash with another serial number in issuerSerial does not pass.
    let signer = pki.signing_key();
    let certificate = signer.certificate();
    let wrong_serial = ua_cryptography_der::sequence([
        ua_cryptography_der::sequence([ua_cryptography_der::explicit(4, certificate.issuer().encoded())]),
        ua_cryptography_der::integer(&(certificate.serial_number() + BigInt::from(1))),
    ]);
    let cert_id = ua_cryptography_der::sequence([
        ua_cryptography_der::algorithm_identifier(oids::DSTU7564_256),
        ua_cryptography_der::octet_string(&recipes::hash(oids::DSTU7564_256, certificate.encoded(), None)),
        wrong_serial,
    ]);
    let attributes = ua_cryptography_der::set_of([
        cms_builder::attribute(oids::CONTENT_TYPE, [ua_cryptography_der::object_identifier(oids::DATA)]),
        cms_builder::attribute(
            oids::MESSAGE_DIGEST,
            [ua_cryptography_der::octet_string(&recipes::hash(
                oids::DSTU7564_256,
                DATA,
                None,
            ))],
        ),
        cms_builder::attribute(
            oids::SIGNING_CERTIFICATE_V2,
            [ua_cryptography_der::sequence([ua_cryptography_der::sequence([
                cert_id,
            ])])],
        ),
    ]);
    let (signer_info, _) = cms_builder::signer_info(&attributes, &signer, oids::DSTU7564_256, &[]).unwrap();
    let forged = cms_builder::signed_data(
        &signer_info,
        oids::DSTU7564_256,
        oids::DATA,
        Some(DATA),
        std::slice::from_ref(certificate),
    );
    let result = cades_verifier::verify(&forged, None, &pki.trusting()).unwrap();
    assert!(!result.is_valid());
    assert!(has_check(
        &result.signatures[0],
        "CMS: signing certificate",
        CheckStatus::Failed
    ));
}

/// Answers every caIssuers address with the same certificates and remembers the addresses asked.
struct RecordingDownloads {
    certificates: Vec<Certificate>,
    urls: RefCell<Vec<String>>,
}

impl CertificateSource for RecordingDownloads {
    fn download_certificates(&self, url: &str) -> Result<Vec<Certificate>, ServiceError> {
        self.urls.borrow_mut().push(url.to_owned());
        Ok(self.certificates.clone())
    }
}

#[test]
fn a_time_stamp_without_the_service_certificate_is_completed_from_ca_issuers() {
    // The shape PrivatBank hands out: CAdES-T with only the signer's certificate, the token without the TSA's, and the
    // provider's whole set (CA and TSA certificates) published at the signer certificate's caIssuers address.
    let pki = Hierarchy::shared();
    let certificate = CertificateBuilder::new(
        pki.signer.certificate.subject().clone(),
        pki.signer.key.public_key().clone(),
    )
    .unwrap()
    .add_key_usage(KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::NON_REPUDIATION)
    .add_authority_info_access(None, Some("http://ca.test/bundle.p7b"))
    .issue(&pki.issuing_ca.certificate, &pki.issuing_ca.key)
    .unwrap();
    let mut time_stamps = TestTimeStamps::new();
    time_stamps.include_certificate = false;
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ..SignatureServices::default()
    };
    let signer = SigningKey::new(pki.signer.key.clone(), vec![certificate]).unwrap();
    let level_t = CadesOptions {
        level: SignatureLevel::T,
        ..CadesOptions::default()
    };
    let rust_made = CadesSigner::new(signer, services).sign(DATA, &level_t).unwrap();

    for signature in [rust_made, read_oracle("package/cades-t-no-tsa-certificate.p7s")] {
        // Offline the token cannot be checked: a warning, and its time is not used.
        let offline = cades_verifier::verify(&signature, None, &ValidationOptions::default()).unwrap();
        let report = &offline.signatures[0];
        assert!(report.is_valid(), "{}", describe_report(report));
        assert!(has_check(
            report,
            "signature time-stamp: service certificate",
            CheckStatus::Warning
        ));
        assert_eq!(report.time_stamp_time, None);

        // With downloads the bundle completes both the time-stamp and the signer's path, in one download.
        let downloads = RecordingDownloads {
            certificates: vec![pki.issuing_ca.certificate.clone(), pki.tsa.certificate.clone()],
            urls: RefCell::new(Vec::new()),
        };
        let options = ValidationOptions {
            trust_anchors: vec![pki.root.certificate.clone()],
            downloads: Some(&downloads),
            ..ValidationOptions::default()
        };
        let online = cades_verifier::verify(&signature, None, &options).unwrap();
        let report = &online.signatures[0];
        assert!(report.is_valid(), "{}", describe_report(report));
        assert!(has_check(
            report,
            "signature time-stamp: signature",
            CheckStatus::Passed
        ));
        assert!(has_check(report, "signer: trust", CheckStatus::Passed));
        assert_eq!(report.time_stamp_time, Some(report.time_stamps[0].token.gen_time()));
        assert_eq!(*downloads.urls.borrow(), ["http://ca.test/bundle.p7b"]);
    }
}

#[test]
fn a_detached_signature_without_data_and_an_untrusted_root_fail() {
    let signature = sign(&options(oids::DSTU7564_256, true, SignatureLevel::B));
    let result = cades_verifier::verify(&signature, None, &ValidationOptions::default()).unwrap();
    assert!(has_check(&result.signatures[0], "content", CheckStatus::Failed));

    let options = ValidationOptions {
        trust_anchors: common::czo_roots(),
        ..ValidationOptions::default()
    };
    let untrusted = cades_verifier::verify(&signature, Some(DATA), &options).unwrap();
    assert!(!untrusted.is_valid());
    assert!(has_check(
        &untrusted.signatures[0],
        "signer: trust",
        CheckStatus::Failed
    ));
}

#[test]
fn level_t_without_a_time_stamping_service_is_refused() {
    let signer = CadesSigner::new(Hierarchy::shared().signing_key(), SignatureServices::default());
    let level_t = CadesOptions {
        level: SignatureLevel::T,
        ..CadesOptions::default()
    };
    assert_eq!(signer.sign(DATA, &level_t), Err(SigningError::NoTimeStampService));
    let level_lt = CadesOptions {
        level: SignatureLevel::LT,
        ..CadesOptions::default()
    };
    let time_stamps = TestTimeStamps::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ..SignatureServices::default()
    };
    let signer = CadesSigner::new(Hierarchy::shared().signing_key(), services);
    assert_eq!(signer.sign(DATA, &level_lt), Err(SigningError::NoOcspService));
}
