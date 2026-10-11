//! The two provider formats of docs/provider-formats.md at the library level: a PrivatBank `.sig` (CAdES-T) and a
//! "Дія" ASiC-E (XAdES-B-LT), as the providers make them (recorded) and as the crate makes them with the providers'
//! key stores, each checked against the provider's profile by an independent recipe and verified by the crate. The
//! command-line side of these tests belongs to the `ua-sign` port.

mod common;

use std::collections::BTreeMap;

use common::xml::{self, ASIC, DS, MANIFEST, XADES};
use common::{
    Hierarchy, TestOcsp, TestTimeStamps, describe, has_check, oracle_certificate, read_oracle, read_zip, recipes,
};
use ua_der::{Asn1Node, tag};
use ua_pki::{
    CadesOptions, CadesSigner, Certificate, CertificateSource, CheckStatus, JksKeyStore, OcspResponse, OcspService,
    ServiceError, SignatureLevel, SignatureServices, SignedFile, SigningKey, ValidationOptions, XadesSigner,
    asic_container, oids, signature_verifier,
};
use ua_xml_c14n::DocumentText;

const PASSWORD: &str = "provider formats";

/// The PrivatBank profile (docs/provider-formats.md, section 1): enveloped CAdES-T, DSTU 4145 with DSTU 7564-256,
/// signingTime as UTCTime, signingCertificateV2 with issuerSerial, only the signer's certificate inside.
fn assert_privatbank_profile(signature: &[u8], data: &[u8], signer: &Certificate) {
    let cms = recipes::read_cms(signature);
    assert_eq!(cms.content_type, oids::DATA);
    assert_eq!(cms.content.as_deref(), Some(data));
    assert_eq!(cms.certificates, [signer.encoded().to_vec()]);
    assert_eq!(cms.signers.len(), 1);
    let info = &cms.signers[0];
    assert_eq!(&info.serial_number, signer.serial_number());
    assert_eq!(info.digest_algorithm, oids::DSTU7564_256);
    assert_eq!(info.signature_algorithm, oids::DSTU4145_WITH_DSTU7564);
    assert!(recipes::verify_cms_signer(info, signer.encoded()));

    let mut signed: Vec<&str> = info.attributes.iter().map(|(oid, _)| oid.as_str()).collect();
    signed.sort();
    let mut expected = [
        oids::CONTENT_TYPE,
        oids::SIGNING_TIME,
        oids::MESSAGE_DIGEST,
        oids::SIGNING_CERTIFICATE_V2,
    ];
    expected.sort();
    assert_eq!(signed, expected);
    assert_eq!(
        Asn1Node::parse(info.signed(oids::SIGNING_TIME)).unwrap().tag(),
        tag::UTC_TIME
    );
    assert_eq!(info.message_digest(), recipes::hash(oids::DSTU7564_256, data, None));

    let attribute = Asn1Node::parse(info.signed(oids::SIGNING_CERTIFICATE_V2)).unwrap();
    let certificates = attribute.child(0).unwrap().children().unwrap();
    assert_eq!(certificates.len(), 1);
    let cert_id = &certificates[0];
    assert_eq!(
        cert_id.child(1).unwrap().to_octet_string().unwrap(),
        recipes::hash(oids::DSTU7564_256, signer.encoded(), None)
    );
    let issuer_serial = cert_id.child(2).unwrap();
    assert_eq!(
        &issuer_serial.child(1).unwrap().to_integer().unwrap(),
        signer.serial_number()
    );
    let names = issuer_serial.child(0).unwrap().children().unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].child(0).unwrap().encoded(), signer.issuer().encoded());

    let unsigned: Vec<&str> = info.unsigned.iter().map(|(oid, _)| oid.as_str()).collect();
    assert_eq!(unsigned, [oids::SIGNATURE_TIME_STAMP_TOKEN]);
    let token = info.unsigned(oids::SIGNATURE_TIME_STAMP_TOKEN);
    let (imprint_algorithm, _, policy) = recipes::read_time_stamp(token);
    assert_eq!(policy, oids::TSP_POLICY_DSTU7564);
    assert_eq!(imprint_algorithm, oids::DSTU7564_256);
    assert!(recipes::imprint_covers(token, &info.signature));
}

/// The "Дія" profile (docs/provider-formats.md, section 2): ASiC-E with one detached XAdES-B-LT, DSTU 4145 with
/// DSTU 7564-256; with a "good" OCSP response about the signer.
fn assert_diia_profile(container: &[u8], name: &str, data: &[u8], signer: &Certificate, issuer: &Certificate) {
    let entries = read_zip(container);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        ["mimetype", name, "META-INF/manifest.xml", "META-INF/signatures001.xml"]
    );
    assert!(entries[0].is_stored);
    assert_eq!(entries[0].content, asic_container::ASIC_E_MIME_TYPE.as_bytes());
    assert_eq!(entries[1].content, data);

    let manifest_text = DocumentText::decode(&entries[2].content).unwrap();
    let manifest = manifest_text.parse().unwrap();
    let listed: Vec<&str> = xml::elements(&manifest, MANIFEST, "file-entry")
        .iter()
        .map(|e| e.attribute((MANIFEST, "full-path")).unwrap())
        .collect();
    assert_eq!(listed, ["/", name]);

    let text = DocumentText::decode(&entries[3].content).unwrap();
    let document = text.parse().unwrap();
    assert!(document.root_element().has_tag_name((ASIC, "XAdESSignatures")));
    let signatures = xml::elements(&document, DS, "Signature");
    assert_eq!(signatures.len(), 1);
    let signature = signatures[0];
    let exclusive = "http://www.w3.org/2001/10/xml-exc-c14n#";

    // SignedInfo: exclusive C14N, DSTU 4145 + DSTU 7564-256, the file and the signed properties.
    let signed_info = xml::child(&signature, DS, "SignedInfo");
    assert_eq!(
        xml::child(&signed_info, DS, "CanonicalizationMethod").attribute("Algorithm"),
        Some(exclusive)
    );
    let signature_method = xml::child(&signed_info, DS, "SignatureMethod").attribute("Algorithm");
    assert_eq!(
        signature_method,
        Some("http://www.w3.org/2001/04/xmldsig-more#dstu4145-dstu7564-256")
    );
    let references: Vec<_> = signed_info
        .children()
        .filter(|n| n.has_tag_name((DS, "Reference")))
        .collect();
    assert_eq!(references.len(), 2);
    assert_eq!(references[0].attribute("URI"), Some(name));
    assert_eq!(
        xml::base64(&xml::child(&references[0], DS, "DigestValue")),
        recipes::hash(oids::DSTU7564_256, data, None)
    );
    assert_eq!(
        references[1].attribute("Type"),
        Some("http://uri.etsi.org/01903#SignedProperties")
    );
    let transform = xml::child(&xml::child(&references[1], DS, "Transforms"), DS, "Transform");
    assert_eq!(transform.attribute("Algorithm"), Some(exclusive));

    let certificate = xml::base64(&xml::child(
        &xml::child(&xml::child(&signature, DS, "KeyInfo"), DS, "X509Data"),
        DS,
        "X509Certificate",
    ));
    assert_eq!(certificate, signer.encoded());
    let qualifying = xml::child(&xml::child(&signature, DS, "Object"), XADES, "QualifyingProperties");
    assert_eq!(
        qualifying.attribute("Target").map(str::to_owned),
        Some(format!("#{}", signature.attribute("Id").unwrap()))
    );

    // SignedProperties: the one the second reference covers; signing time, certificate, data format.
    let properties = xml::child(&qualifying, XADES, "SignedProperties");
    assert_eq!(
        references[1].attribute("URI").map(str::to_owned),
        Some(format!("#{}", properties.attribute("Id").unwrap()))
    );
    assert_eq!(
        xml::base64(&xml::child(&references[1], DS, "DigestValue")),
        recipes::hash(oids::DSTU7564_256, &xml::exclusive(properties), None)
    );
    let signature_properties = xml::child(&properties, XADES, "SignedSignatureProperties");
    let signing_time = xml::text(&xml::child(&signature_properties, XADES, "SigningTime"));
    assert!(time::OffsetDateTime::parse(&signing_time, &time::format_description::well_known::Rfc3339).is_ok());
    let cert_digest = xml::child(
        &xml::child(
            &xml::child(&signature_properties, XADES, "SigningCertificateV2"),
            XADES,
            "Cert",
        ),
        XADES,
        "CertDigest",
    );
    assert_eq!(
        xml::base64(&xml::child(&cert_digest, DS, "DigestValue")),
        recipes::hash(oids::DSTU7564_256, signer.encoded(), None)
    );
    let format = xml::child(
        &xml::child(&properties, XADES, "SignedDataObjectProperties"),
        XADES,
        "DataObjectFormat",
    );
    assert_eq!(
        format.attribute("ObjectReference").map(str::to_owned),
        Some(format!("#{}", references[0].attribute("Id").unwrap()))
    );
    assert!(!xml::text(&xml::child(&format, XADES, "MimeType")).is_empty());

    // The DSTU 4145 signature over the canonical SignedInfo.
    let key = recipes::read_public_key(signer.encoded());
    let value = xml::base64(&xml::child(&signature, DS, "SignatureValue"));
    assert!(recipes::verify_dstu4145(
        &key,
        &recipes::hash(oids::DSTU7564_256, &xml::exclusive(signed_info), None),
        &value
    ));

    // Level LT: the time-stamp over the canonical SignatureValue, the CA certificate, a good OCSP response.
    let unsigned = xml::child(
        &xml::child(&qualifying, XADES, "UnsignedProperties"),
        XADES,
        "UnsignedSignatureProperties",
    );
    let stamp = xml::child(&unsigned, XADES, "SignatureTimeStamp");
    assert_eq!(
        xml::child(&stamp, DS, "CanonicalizationMethod").attribute("Algorithm"),
        Some(exclusive)
    );
    let token = xml::base64(&xml::child(&stamp, XADES, "EncapsulatedTimeStamp"));
    assert_eq!(recipes::read_time_stamp(&token).2, oids::TSP_POLICY_DSTU7564);
    assert!(recipes::imprint_covers(
        &token,
        &xml::exclusive(xml::child(&signature, DS, "SignatureValue"))
    ));
    let values = xml::child(&unsigned, XADES, "CertificateValues");
    assert!(
        values
            .children()
            .filter(|n| n.is_element())
            .any(|value| xml::base64(&value) == issuer.encoded())
    );
    let ocsp = xml::elements(&document, XADES, "EncapsulatedOCSPValue");
    assert!(!ocsp.is_empty());
    let about_signer: Vec<u8> = ocsp
        .iter()
        .flat_map(|value| recipes::ocsp_statuses(&recipes::read_ocsp_response(&xml::base64(value))))
        .filter(|(serial, _)| serial == signer.serial_number())
        .map(|(_, status)| status)
        .collect();
    assert_eq!(about_signer, [0]);
}

/// caIssuers downloads and OCSP answered from recordings, as `LocalPkiServer` answered the C# tests.
struct RecordedServices {
    bundles: BTreeMap<String, Vec<Certificate>>,
    responses: Vec<(Certificate, OcspResponse)>,
}

impl CertificateSource for RecordedServices {
    fn download_certificates(&self, url: &str) -> Result<Vec<Certificate>, ServiceError> {
        Ok(self.bundles.get(url).cloned().unwrap_or_default())
    }
}

impl OcspService for RecordedServices {
    fn find_response(
        &self,
        certificate: &Certificate,
        _: &Certificate,
        _: &str,
    ) -> Result<Option<OcspResponse>, ServiceError> {
        Ok(self
            .responses
            .iter()
            .find(|(known, _)| known == certificate)
            .map(|(_, response)| response.clone()))
    }
}

fn bank_services() -> RecordedServices {
    let bundle = ua_pki::certificate_files::parse(&read_oracle("providers/privatbank/ca.p7b")).unwrap();
    RecordedServices {
        bundles: BTreeMap::from([("http://127.0.0.1:18089/ca.p7b".to_owned(), bundle)]),
        responses: vec![
            (
                oracle_certificate("providers/privatbank/customer.cer"),
                OcspResponse::load(&read_oracle("providers/privatbank/customer-ocsp.der")).unwrap(),
            ),
            (
                Hierarchy::shared().issuing_ca.certificate.clone(),
                OcspResponse::load(&read_oracle("hierarchy/ocsp-issuing-ca.der")).unwrap(),
            ),
        ],
    }
}

#[test]
fn a_privatbank_sig_as_the_bank_makes_it_verifies() {
    let pki = Hierarchy::shared();
    let document = read_oracle("providers/doc.txt");
    let customer = oracle_certificate("providers/privatbank/customer.cer");
    for file in [
        "providers/privatbank/doc.txt.sig",
        "providers/privatbank/doc.txt.ua-sign.sig",
    ] {
        assert_privatbank_profile(&read_oracle(file), &document, &customer);
    }
    let signature = read_oracle("providers/privatbank/doc.txt.sig");
    let none = |_: Option<&str>| None;

    // Offline: neither the CA's nor the TSA's certificate is in the signature.
    let result = signature_verifier::verify(&signature, &none, &ValidationOptions::default()).unwrap();
    assert!(result.is_valid(), "{}", describe(&result));
    assert!(has_check(
        &result.signatures[0],
        "signature time-stamp: service certificate",
        CheckStatus::Warning
    ));
    let root_only = ValidationOptions {
        trust_anchors: vec![pki.root.certificate.clone()],
        ..ValidationOptions::default()
    };
    let result = signature_verifier::verify(&signature, &none, &root_only).unwrap();
    assert!(!result.is_valid());
    assert!(has_check(&result.signatures[0], "signer: trust", CheckStatus::Failed));

    // Online: the caIssuers bundle completes both; OCSP answers for the customer.
    let services = bank_services();
    let online = ValidationOptions {
        trust_anchors: vec![pki.root.certificate.clone()],
        downloads: Some(&services),
        online_ocsp: Some(&services),
        ..ValidationOptions::default()
    };
    let result = signature_verifier::verify(&signature, &none, &online).unwrap();
    assert!(result.is_valid(), "{}", describe(&result));
    let report = &result.signatures[0];
    assert!(has_check(
        report,
        "signature time-stamp: signature",
        CheckStatus::Passed
    ));
    assert!(has_check(report, "signer: trust", CheckStatus::Passed));
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.name == "signer: revocation of 'Test Bank Customer'"
                && c.details.starts_with("good, online response"))
    );

    // The document inside is changed: invalid.
    let mut tampered = signature.clone();
    let at = tampered
        .windows(document.len())
        .position(|window| window == document)
        .unwrap();
    tampered[at] ^= 1;
    assert!(
        !signature_verifier::verify(&tampered, &none, &online)
            .unwrap()
            .is_valid()
    );
}

#[test]
fn the_crate_makes_a_privatbank_sig_with_the_bank_key_store() {
    let pki = Hierarchy::shared();
    let store = JksKeyStore::load(&read_oracle("providers/privatbank/key.jks"), PASSWORD).unwrap();
    let signer = SigningKey::from_jks(&store, PASSWORD, None, None).unwrap();
    let customer = oracle_certificate("providers/privatbank/customer.cer");
    // The chain is rebuilt from the customer's certificate; the key-agreement certificate is left out.
    assert_eq!(
        signer.chain(),
        [
            customer.clone(),
            pki.issuing_ca.certificate.clone(),
            pki.root.certificate.clone()
        ]
    );

    let document = read_oracle("providers/doc.txt");
    let time_stamps = TestTimeStamps::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ..SignatureServices::default()
    };
    let options = CadesOptions {
        level: SignatureLevel::T,
        ..CadesOptions::default()
    };
    let signature = CadesSigner::new(signer, services).sign(&document, &options).unwrap();
    assert_privatbank_profile(&signature, &document, &customer);

    let services = bank_services();
    let online = ValidationOptions {
        trust_anchors: vec![pki.root.certificate.clone()],
        downloads: Some(&services),
        online_ocsp: Some(&services),
        ..ValidationOptions::default()
    };
    let result = signature_verifier::verify(&signature, &|_: Option<&str>| None, &online).unwrap();
    assert!(result.is_valid(), "{}", describe(&result));
    assert!(
        result.signatures[0]
            .checks
            .iter()
            .all(|c| c.status != CheckStatus::Failed)
    );
    assert!(has_check(
        &result.signatures[0],
        "signature time-stamp: signature",
        CheckStatus::Passed
    ));
}

#[test]
fn a_diia_asic_e_as_diia_makes_it_verifies() {
    let pki = Hierarchy::shared();
    let document = read_oracle("providers/doc.txt");
    let container = read_oracle("providers/diia/doc.txt.asice");
    for file in ["providers/diia/doc.txt.asice", "providers/diia/doc.txt.ua-sign.asice"] {
        assert_diia_profile(
            &read_oracle(file),
            "doc.txt",
            &document,
            &pki.signer.certificate,
            &pki.issuing_ca.certificate,
        );
    }
    let root_only = ValidationOptions {
        trust_anchors: vec![pki.root.certificate.clone()],
        ..ValidationOptions::default()
    };
    let none = |_: Option<&str>| None;
    let result = signature_verifier::verify(&container, &none, &root_only).unwrap();
    assert!(result.is_valid(), "{}", describe(&result));
    let checks: Vec<String> = result
        .signatures
        .iter()
        .flat_map(|r| {
            r.checks
                .iter()
                .map(|c| format!("{:?} {}: {}", c.status, c.name, c.details))
        })
        .collect();
    assert!(checks.contains(&"Passed manifest: lists all 1 data files".to_owned()));
    assert!(
        checks
            .iter()
            .any(|c| c.starts_with("Passed signature time-stamp: signature:"))
    );
    // The response with a zero issuerKeyHash counts; "Дія" embeds none about its CA.
    assert!(
        checks
            .iter()
            .any(|c| c.starts_with("Passed signer: revocation of 'Test Signer': good, embedded"))
    );
    assert!(
        checks
            .iter()
            .any(|c| c.starts_with("Warning signer: revocation of 'Test Issuing CA'"))
    );

    // The document in the container is changed: invalid.
    let entries = read_zip(&container);
    let rewritten: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|e| {
            (
                e.name.as_str(),
                if e.name == "doc.txt" {
                    "Інший документ\n".as_bytes()
                } else {
                    e.content.as_slice()
                },
            )
        })
        .collect();
    let result = signature_verifier::verify(&common::write_zip(&rewritten), &none, &root_only).unwrap();
    assert!(!result.is_valid());
    assert!(
        result
            .signatures
            .iter()
            .any(|r| has_check(r, "reference 'doc.txt'", CheckStatus::Failed))
    );
}

#[test]
fn the_crate_makes_a_diia_asic_e_with_the_diia_key_store() {
    let pki = Hierarchy::shared();
    let store = JksKeyStore::load(&read_oracle("providers/diia/key.jks"), PASSWORD).unwrap();
    let signer = SigningKey::from_jks(&store, PASSWORD, Some("signer"), None).unwrap();
    let document = read_oracle("providers/doc.txt");
    let files = [SignedFile {
        name: "doc.txt".to_owned(),
        content: document.clone(),
    }];
    let time_stamps = TestTimeStamps::new();
    let ocsp = TestOcsp::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ocsp: Some(&ocsp),
        ..SignatureServices::default()
    };
    let signature = XadesSigner::new(signer, services)
        .sign(&files, oids::DSTU7564_256, SignatureLevel::LT)
        .unwrap();
    let container = asic_container::create_asic_e(&files, &signature).unwrap();
    assert_diia_profile(
        &container,
        "doc.txt",
        &document,
        &pki.signer.certificate,
        &pki.issuing_ca.certificate,
    );

    // Offline, with the root only: everything the check needs is in the container.
    let root_only = ValidationOptions {
        trust_anchors: vec![pki.root.certificate.clone()],
        ..ValidationOptions::default()
    };
    let result = signature_verifier::verify(&container, &|_: Option<&str>| None, &root_only).unwrap();
    assert!(result.is_valid(), "{}", describe(&result));
    let report = &result.signatures[1];
    assert!(
        report
            .format
            .as_deref()
            .unwrap()
            .contains("XAdES-B-LT, detached, DSTU 7564-256")
    );
    for subject in ["Test Signer", "Test Issuing CA"] {
        let name = format!("signer: revocation of '{subject}'");
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.name == name && c.details.starts_with("good, embedded")),
            "{subject}"
        );
    }
}
