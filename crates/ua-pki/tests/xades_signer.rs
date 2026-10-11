//! XAdES made by the crate: the same document structure as the C# XadesSigner writes (its recorded output), checked
//! with the canonicalizer and the independent recipes; XAdES of the C# test builder checked by the crate's verifier;
//! tampering and signature wrapping.

mod common;

use common::xml::{self, DS, XADES};
use common::{Hierarchy, TestOcsp, TestTimeStamps, describe_report, has_check, read_oracle, recipes};
use ua_pki::{
    CheckStatus, SignatureLevel, SignatureServices, SignedFile, ValidationOptions, VerificationReport, XadesSigner,
    oids, xades_verifier,
};
use ua_xml_c14n::DocumentText;

fn files() -> [SignedFile; 2] {
    [
        SignedFile {
            name: "заява.txt".to_owned(),
            content: "Текст заяви".as_bytes().to_vec(),
        },
        SignedFile {
            name: "data file.bin".to_owned(),
            content: vec![0, 1, 2, 3, 255],
        },
    ]
}

fn sign(hash_oid: &str, level: SignatureLevel, files: &[SignedFile]) -> Vec<u8> {
    let time_stamps = TestTimeStamps::new();
    let ocsp = TestOcsp::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ocsp: Some(&ocsp),
        ..SignatureServices::default()
    };
    XadesSigner::new(Hierarchy::shared().signing_key(), services)
        .sign_to_bytes(files, hash_oid, level)
        .unwrap()
}

fn resolve(files: &[SignedFile]) -> impl Fn(&str) -> Option<Vec<u8>> + '_ {
    move |name: &str| {
        files
            .iter()
            .find(|file| file.name == name)
            .map(|file| file.content.clone())
    }
}

fn verify(
    xml: &[u8],
    resolve: &dyn Fn(&str) -> Option<Vec<u8>>,
    options: &ValidationOptions<'_>,
) -> Vec<VerificationReport> {
    let text = DocumentText::decode(xml).unwrap();
    let document = text.parse().unwrap();
    xades_verifier::verify(&document, resolve, options)
}

#[test]
fn the_document_has_the_structure_the_csharp_signer_writes() {
    for (hash, hash_oid) in [("dstu7564", oids::DSTU7564_256), ("gost34311", oids::GOST34311)] {
        for (level_name, level) in [
            ("b", SignatureLevel::B),
            ("t", SignatureLevel::T),
            ("lt", SignatureLevel::LT),
        ] {
            let csharp = String::from_utf8(read_oracle(&format!("package/xades-{hash}-{level_name}.xml"))).unwrap();
            let rust = String::from_utf8(sign(hash_oid, level, &files())).unwrap();
            assert_eq!(xml::skeleton(&rust), xml::skeleton(&csharp), "{hash} {level_name}");
        }
    }
}

#[test]
fn the_crate_signature_verifies_with_the_canonicalizer_and_the_recipe() {
    let files = files();
    for hash_oid in [oids::DSTU7564_256, oids::GOST34311] {
        let signature = sign(hash_oid, SignatureLevel::B, &files);
        let text = DocumentText::decode(&signature).unwrap();
        let document = text.parse().unwrap();
        let certificate = xml::base64(&xml::element(&document, DS, "X509Certificate"));
        let key = recipes::read_public_key(&certificate);

        // Each reference digest, recomputed with exclusive C14N for the signed properties.
        let references = xml::elements(&document, DS, "Reference");
        for reference in &references {
            let uri = reference.attribute("URI").unwrap();
            let content = match uri.strip_prefix('#') {
                Some(id) => xml::exclusive(xml::by_id(&document, id)),
                None => {
                    let name = if uri == "data%20file.bin" {
                        "data file.bin"
                    } else {
                        "заява.txt"
                    };
                    resolve(&files)(name).unwrap()
                }
            };
            assert_eq!(
                xml::base64(&xml::child(reference, DS, "DigestValue")),
                recipes::hash(hash_oid, &content, None)
            );
        }
        assert!(
            references
                .iter()
                .any(|reference| reference.attribute("URI") == Some("data%20file.bin"))
        );

        let signed_info = xml::exclusive(xml::element(&document, DS, "SignedInfo"));
        let value = xml::base64(&xml::element(&document, DS, "SignatureValue"));
        assert!(recipes::verify_dstu4145(
            &key,
            &recipes::hash(hash_oid, &signed_info, None),
            &value
        ));
    }
}

#[test]
fn the_crate_signature_verifies_by_the_crate() {
    let pki = Hierarchy::shared();
    let files = files();
    let rows = [
        (oids::DSTU7564_256, SignatureLevel::B),
        (oids::DSTU7564_256, SignatureLevel::T),
        (oids::DSTU7564_256, SignatureLevel::LT),
        (oids::GOST34311, SignatureLevel::LT),
    ];
    for (hash_oid, level) in rows {
        let signature = sign(hash_oid, level, &files);
        let reports = verify(&signature, &resolve(&files), &pki.trusting());
        assert_eq!(reports.len(), 1);
        let report = &reports[0];
        assert!(report.is_valid(), "{}", describe_report(report));
        assert_eq!(report.time_stamp_time.is_some(), level >= SignatureLevel::T);
        let level_name = format!("XAdES-B-{level:?}");
        assert!(report.format.as_deref().unwrap().starts_with(&format!("{level_name},")));
        if level == SignatureLevel::LT {
            assert!(
                !report
                    .checks
                    .iter()
                    .any(|c| c.name.starts_with("signer:") && c.status != CheckStatus::Passed)
            );

            // The time-stamp is a token over the canonical ds:SignatureValue.
            let text = DocumentText::decode(&signature).unwrap();
            let document = text.parse().unwrap();
            let token = xml::base64(&xml::element(&document, XADES, "EncapsulatedTimeStamp"));
            let signature_value = xml::exclusive(xml::element(&document, DS, "SignatureValue"));
            assert!(recipes::imprint_covers(&token, &signature_value));
            let known: Vec<Vec<u8>> = pki.all_certificates().iter().map(|c| c.encoded().to_vec()).collect();
            for value in xml::elements(&document, XADES, "EncapsulatedOCSPValue") {
                let basic = recipes::read_ocsp_response(&xml::base64(&value));
                assert!(recipes::verify_ocsp(
                    &basic,
                    &recipes::find_ocsp_responder(&basic, &known)
                ));
            }
        }
    }
}

#[test]
fn the_test_builder_signatures_verify_by_the_crate() {
    let pki = Hierarchy::shared();
    let data = read_oracle("xades/data.txt");
    let resolve = |name: &str| (name == "data.txt").then(|| data.clone());
    for (file, is_long_term) in [
        ("xades/xades-dstu7564-b.xml", false),
        ("xades/xades-gost34311-t.xml", false),
        ("xades/xades-dstu7564-lt.xml", true),
    ] {
        let reports = verify(&read_oracle(file), &resolve, &pki.trusting());
        let report = &reports[0];
        assert!(report.is_valid(), "{file}: {}", describe_report(report));
        if is_long_term {
            let passed = report
                .checks
                .iter()
                .filter(|c| c.name.starts_with("signer: revocation") && c.status == CheckStatus::Passed)
                .count();
            assert_eq!(passed, 2);
        }
    }
}

#[test]
fn a_tampered_file_fails_its_reference() {
    let files = files();
    let signature = sign(oids::DSTU7564_256, SignatureLevel::B, &files);
    let tampered = |name: &str| {
        if name == "data file.bin" {
            Some(vec![0, 1, 2, 3, 254])
        } else {
            resolve(&files)(name)
        }
    };
    let report = &verify(&signature, &tampered, &ValidationOptions::default())[0];
    assert!(!report.is_valid());
    assert!(has_check(report, "reference 'data%20file.bin'", CheckStatus::Failed));
    assert!(has_check(
        report,
        "reference '%D0%B7%D0%B0%D1%8F%D0%B2%D0%B0.txt'",
        CheckStatus::Passed
    ));
}

#[test]
fn a_changed_signed_property_or_signature_value_fails() {
    let files = files();
    let file = &files[..1];
    let signature = String::from_utf8(sign(oids::DSTU7564_256, SignatureLevel::B, file)).unwrap();
    let start = signature.find("<xades:SigningTime>").unwrap() + "<xades:SigningTime>".len();
    let end = signature.find("</xades:SigningTime>").unwrap();
    let changed = format!("{}2001-01-01T00:00:00Z{}", &signature[..start], &signature[end..]);
    let report = &verify(changed.as_bytes(), &resolve(file), &ValidationOptions::default())[0];
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name.ends_with("-SignedProperties'") && c.status == CheckStatus::Failed)
    );

    let start = signature.find("-SignatureValue\">").unwrap() + "-SignatureValue\">".len();
    let end = start + signature[start..].find('<').unwrap();
    let mut value = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &signature[start..end]).unwrap();
    value[7] ^= 1;
    let value = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value);
    let changed = format!("{}{value}{}", &signature[..start], &signature[end..]);
    let report = &verify(changed.as_bytes(), &resolve(file), &ValidationOptions::default())[0];
    assert!(has_check(report, "signature", CheckStatus::Failed));
}

#[test]
fn a_duplicate_id_is_refused() {
    // Signature wrapping: a second element with the Id of the signed properties (carrying a forged signing time) must
    // not be accepted as the covered one.
    let files = files();
    let file = &files[..1];
    let signature = String::from_utf8(sign(oids::DSTU7564_256, SignatureLevel::B, file)).unwrap();
    let start = signature.find("<xades:SignedProperties").unwrap();
    let end = signature.find("</xades:SignedProperties>").unwrap() + "</xades:SignedProperties>".len();
    let copy = signature[start..end].replacen(
        "<xades:SignedProperties",
        &format!("<xades:SignedProperties xmlns:xades=\"{XADES}\""),
        1,
    );
    let time_start = copy.find("<xades:SigningTime>").unwrap() + "<xades:SigningTime>".len();
    let time_end = copy.find("</xades:SigningTime>").unwrap();
    let copy = format!("{}2001-01-01T00:00:00Z{}", &copy[..time_start], &copy[time_end..]);
    let close = signature.rfind("</ds:Signature>").unwrap();
    let wrapped = format!(
        "{}<ds:Object>{copy}</ds:Object>{}",
        &signature[..close],
        &signature[close..]
    );

    let report = &verify(wrapped.as_bytes(), &resolve(file), &ValidationOptions::default())[0];
    assert!(!report.is_valid());
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "structure" && c.details.contains("Several elements"))
    );
}

#[test]
fn a_missing_file_is_reported() {
    let files = files();
    let signature = sign(oids::DSTU7564_256, SignatureLevel::B, &files[..1]);
    let report = &verify(&signature, &|_: &str| None, &ValidationOptions::default())[0];
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.details == "the referenced file was not given" && c.status == CheckStatus::Failed)
    );
}
