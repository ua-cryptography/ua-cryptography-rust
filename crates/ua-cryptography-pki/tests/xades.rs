//! XAdES signatures of the C# test builder (`xades/`, the synthetic hierarchy) — detached next to the data and inside
//! ASiC-E — checked by the recipe of docs/signature-formats.md, sections 7 and 8, with `roxmltree`,
//! `ua-cryptography-xml-c14n` and `ua-cryptography-dstu4145`: every ds:Reference digest, the signing certificate
//! digest, the DSTU 4145 signature over the canonical ds:SignedInfo, the signature time-stamp and the long-term
//! validation values.

mod common;

use common::xml::{self, ASIC, DS, MANIFEST, XADES};
use common::{Hierarchy, read_oracle, read_zip, recipes};
use ua_cryptography_pki::{algorithms, asic_container, oids};
use ua_cryptography_xml_c14n::DocumentText;

const DATA_NAME: &str = "data.txt";

fn hash_name(hash_oid: &str) -> &'static str {
    if hash_oid == oids::GOST34311 {
        "gost34311"
    } else {
        "dstu7564"
    }
}

/// The signature document text and the detached data its references name.
fn create(hash_oid: &str, is_asic_e: bool, level: &str) -> (DocumentText, Vec<(String, Vec<u8>)>) {
    if !is_asic_e {
        let xml = read_oracle(&format!("xades/xades-{}-{level}.xml", hash_name(hash_oid)));
        let data = vec![(DATA_NAME.to_owned(), read_oracle("xades/data.txt"))];
        return (DocumentText::decode(&xml).unwrap(), data);
    }
    let entries = read_zip(&read_oracle(&format!(
        "xades/asice-{}-{level}.asice",
        hash_name(hash_oid)
    )));
    assert_eq!(entries[0].name, "mimetype");
    assert!(entries[0].is_stored);
    assert_eq!(entries[0].content, asic_container::ASIC_E_MIME_TYPE.as_bytes());

    // The manifest lists the container itself and every data file.
    let manifest = entries.iter().find(|e| e.name == "META-INF/manifest.xml").unwrap();
    let manifest_text = DocumentText::decode(&manifest.content).unwrap();
    let manifest = manifest_text.parse().unwrap();
    let listed: Vec<&str> = xml::elements(&manifest, MANIFEST, "file-entry")
        .iter()
        .map(|e| e.attribute((MANIFEST, "full-path")).unwrap())
        .collect();
    assert!(listed.contains(&"/"));
    let data: Vec<(String, Vec<u8>)> = entries
        .iter()
        .filter(|e| e.name != "mimetype" && !e.name.starts_with("META-INF/"))
        .map(|e| (e.name.clone(), e.content.clone()))
        .collect();
    assert!(data.iter().all(|(name, _)| listed.contains(&name.as_str())));

    let signatures: Vec<_> = entries
        .iter()
        .filter(|e| e.name.starts_with("META-INF/signatures") && e.name.ends_with(".xml"))
        .collect();
    assert_eq!(signatures.len(), 1);
    let text = DocumentText::decode(&signatures[0].content).unwrap();
    let root_is_asic = {
        let document = text.parse().unwrap();
        document.root_element().has_tag_name((ASIC, "XAdESSignatures"))
    };
    assert!(root_is_asic);
    (text, data)
}

fn detached<'a>(data: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
    &data.iter().find(|(known, _)| known == name).unwrap().1
}

#[test]
fn signatures_verify_by_the_recipe() {
    for (hash_oid, is_asic_e) in [
        (oids::DSTU7564_256, false),
        (oids::GOST34311, false),
        (oids::DSTU7564_256, true),
    ] {
        let (text, data) = create(hash_oid, is_asic_e, "lt");
        let document = text.parse().unwrap();
        assert_eq!(xml::elements(&document, DS, "Signature").len(), 1);
        let signature_method = xml::element(&document, DS, "SignatureMethod")
            .attribute("Algorithm")
            .unwrap();
        assert_eq!(signature_method, algorithms::xml_signature_method(hash_oid).unwrap());
        let signature_hash = algorithms::hash_of_xml_algorithm(signature_method).unwrap();
        let certificate = xml::base64(&xml::element(&document, DS, "X509Certificate"));
        let key = recipes::read_public_key(&certificate);

        // Every reference: the detached data file and the signed properties; XML digests keep the hash bytes as they are.
        let signed_info = xml::element(&document, DS, "SignedInfo");
        for reference in signed_info.children().filter(|n| n.has_tag_name((DS, "Reference"))) {
            let uri = reference.attribute("URI").unwrap();
            let content = match uri.strip_prefix('#') {
                Some(id) => xml::exclusive(xml::by_id(&document, id)),
                None => detached(&data, uri).to_vec(),
            };
            let method = xml::child(&reference, DS, "DigestMethod")
                .attribute("Algorithm")
                .unwrap();
            let hash = recipes::hash(algorithms::hash_of_xml_algorithm(method).unwrap(), &content, None);
            assert_eq!(xml::base64(&xml::child(&reference, DS, "DigestValue")), hash);
        }

        // The signed properties bind the signature to this very certificate.
        let cert_digest = xml::element(&document, XADES, "CertDigest");
        let method = xml::child(&cert_digest, DS, "DigestMethod")
            .attribute("Algorithm")
            .unwrap();
        let expected = recipes::hash(algorithms::hash_of_xml_algorithm(method).unwrap(), &certificate, None);
        assert_eq!(xml::base64(&xml::child(&cert_digest, DS, "DigestValue")), expected);

        // The signature itself, over the canonical SignedInfo.
        let mut canonical = xml::exclusive(signed_info);
        let mut value = xml::base64(&xml::element(&document, DS, "SignatureValue"));
        assert_eq!(value.len(), 64); // m = 257: r and s of 32 bytes each
        assert!(recipes::verify_dstu4145(
            &key,
            &recipes::hash(signature_hash, &canonical, None),
            &value
        ));

        // A single changed byte of the signed data or of the signature breaks it.
        let middle = canonical.len() / 2;
        canonical[middle] ^= 1;
        assert!(!recipes::verify_dstu4145(
            &key,
            &recipes::hash(signature_hash, &canonical, None),
            &value
        ));
        value[5] ^= 1;
        let original = recipes::hash(signature_hash, &xml::exclusive(signed_info), None);
        assert!(!recipes::verify_dstu4145(&key, &original, &value));
    }
}

#[test]
fn tampered_data_breaks_the_reference() {
    let (text, _) = create(oids::DSTU7564_256, false, "b");
    let document = text.parse().unwrap();
    let reference = xml::elements(&document, DS, "Reference")
        .into_iter()
        .find(|r| r.attribute("URI") == Some(DATA_NAME))
        .unwrap();
    let expected = xml::base64(&xml::child(&reference, DS, "DigestValue"));
    assert_ne!(expected, recipes::hash(oids::DSTU7564_256, b"tesT", None));
    assert_eq!(expected, recipes::hash(oids::DSTU7564_256, b"test", None));
}

#[test]
fn the_signer_certificate_is_issued_by_the_embedded_ca() {
    let (text, _) = create(oids::DSTU7564_256, false, "lt");
    let document = text.parse().unwrap();
    let certificate = xml::base64(&xml::element(&document, DS, "X509Certificate"));
    let values: Vec<Vec<u8>> = xml::elements(&document, XADES, "EncapsulatedX509Certificate")
        .iter()
        .map(xml::base64)
        .collect();
    let issuer = recipes::names(&certificate).1;
    let issuers: Vec<&Vec<u8>> = values.iter().filter(|c| recipes::names(c).0 == issuer).collect();
    assert_eq!(issuers.len(), 1);
    assert!(recipes::verify_certificate(&certificate, issuers[0]));
    let root = vec![Hierarchy::shared().root.certificate.encoded().to_vec()];
    assert!(recipes::chains_to_trusted(&certificate, &values, &root));
}

#[test]
fn the_time_stamp_covers_the_signature() {
    // XAdES-T: the time-stamp's message imprint is the hash of the canonical ds:SignatureValue element.
    for hash_oid in [oids::DSTU7564_256, oids::GOST34311] {
        let (text, _) = create(hash_oid, false, "t");
        let document = text.parse().unwrap();
        assert!(xml::elements(&document, XADES, "CertificateValues").is_empty());
        let stamp = xml::element(&document, XADES, "SignatureTimeStamp");
        let token = xml::base64(&xml::child(&stamp, XADES, "EncapsulatedTimeStamp"));
        assert!(recipes::imprint_covers(
            &token,
            &xml::exclusive(xml::element(&document, DS, "SignatureValue"))
        ));
        let token = recipes::read_cms(&token);
        let tsa = token.certificates.first().expect("the TSA certificate is in the token");
        assert!(recipes::verify_cms_signer(&token.signers[0], tsa));
    }
}

#[test]
fn revocation_values_are_signed_and_good() {
    // XAdES-B-LT: the OCSP values are signed by their responders and say "good" for the signer and its CA.
    let (text, _) = create(oids::DSTU7564_256, false, "lt");
    let document = text.parse().unwrap();
    let signer = xml::base64(&xml::element(&document, DS, "X509Certificate"));
    let mut known = vec![signer.clone()];
    known.extend(
        xml::elements(&document, XADES, "EncapsulatedX509Certificate")
            .iter()
            .map(xml::base64),
    );

    let mut covered = Vec::new();
    for value in xml::elements(&document, XADES, "EncapsulatedOCSPValue") {
        let basic = recipes::read_ocsp_response(&xml::base64(&value));
        assert!(recipes::verify_ocsp(
            &basic,
            &recipes::find_ocsp_responder(&basic, &known)
        ));
        let statuses = recipes::ocsp_statuses(&basic);
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1, 0); // good
        covered.push(
            known
                .iter()
                .find(|c| recipes::serial_number(c) == statuses[0].0)
                .unwrap()
                .clone(),
        );
    }
    assert!(covered.contains(&signer));
    let issuer = recipes::names(&signer).1;
    assert!(covered.iter().any(|c| recipes::names(c).0 == issuer));
}

#[test]
fn the_builder_document_canonicalizes_as_microsoft_canonicalizes_it() {
    // Microsoft's exclusive C14N of every element and inclusive C14N of the whole document, recorded.
    let oracle = common::read_json("xades/c14n-xades-dstu7564-lt.json");
    let xml = read_oracle(oracle["document"].as_str().unwrap());
    let text = DocumentText::decode(&xml).unwrap();
    let document = text.parse().unwrap();
    let elements: Vec<_> = document.descendants().filter(|node| node.is_element()).collect();
    let expected = oracle["elements"].as_array().unwrap();
    assert_eq!(elements.len(), expected.len());
    for (element, expected) in elements.iter().zip(expected) {
        assert_eq!(element.tag_name().name(), expected["localName"].as_str().unwrap());
        let canonical = String::from_utf8(xml::exclusive(*element)).unwrap();
        assert_eq!(
            canonical,
            expected["excC14n"].as_str().unwrap(),
            "{}",
            expected["index"]
        );
    }
    let inclusive = ua_cryptography_xml_c14n::canonicalize(
        document.root(),
        ua_cryptography_xml_c14n::Algorithm::Inclusive,
        &[],
        None,
    );
    assert_eq!(
        String::from_utf8(inclusive).unwrap(),
        oracle["inclusiveC14n"].as_str().unwrap()
    );
}
