//! CAdES signatures of the C# test builder (`cades/`, the synthetic hierarchy) checked by the recipe of
//! docs/signature-formats.md, section 9, written with `ua-der` and `ua-dstu4145` alone: messageDigest binds the data,
//! signingCertificateV2 the certificate, and the DSTU 4145 signature covers the DER signed attributes. Time-stamps,
//! references and OCSP values are checked as well.

mod common;

use common::{Hierarchy, read_oracle, read_zip, recipes};
use ua_der::Asn1Node;
use ua_pki::{algorithms, asic_container, oids};

const DATA: &[u8] = b"test";

fn hash_name(hash_oid: &str) -> &'static str {
    if hash_oid == oids::GOST34311 {
        "gost34311"
    } else {
        "dstu7564"
    }
}

/// The CMS of a builder signature and the signed data, wherever it is kept.
fn create(hash_oid: &str, is_enveloped: bool, level: &str, has_content_time_stamp: bool) -> (recipes::Cms, Vec<u8>) {
    let packaging = if is_enveloped { "enveloped" } else { "detached" };
    let suffix = if has_content_time_stamp { "-content-ts" } else { "" };
    let file = format!("cades/cades-{}-{packaging}-{level}{suffix}.p7s", hash_name(hash_oid));
    let cms = recipes::read_cms(&read_oracle(&file));
    assert_eq!(cms.content_type, oids::DATA);
    let data = match &cms.content {
        Some(content) => content.clone(),
        None => read_oracle("cades/data.txt"),
    };
    assert_eq!(cms.content.is_none(), !is_enveloped);
    (cms, data)
}

#[test]
fn signatures_verify_by_the_recipe() {
    for (hash_oid, is_enveloped) in [
        (oids::DSTU7564_256, true),
        (oids::DSTU7564_256, false),
        (oids::GOST34311, true),
        (oids::GOST34311, false),
    ] {
        let (cms, data) = create(hash_oid, is_enveloped, "b", false);
        let signer = &cms.signers[0];
        assert_eq!(signer.digest_algorithm, hash_oid);
        assert_eq!(
            signer.signature_algorithm,
            algorithms::signature_algorithm_for(hash_oid).unwrap()
        );
        let certificate = &cms.certificates[0];
        let key = recipes::read_public_key(certificate);

        // contentType and messageDigest bind the signed attributes to the data; digests keep the hash bytes as they are.
        assert_eq!(
            Asn1Node::parse(signer.signed(oids::CONTENT_TYPE))
                .unwrap()
                .to_oid()
                .unwrap(),
            oids::DATA
        );
        assert_eq!(data, DATA);
        assert_eq!(signer.message_digest(), recipes::hash(hash_oid, &data, None));
        assert_ne!(signer.message_digest(), recipes::hash(hash_oid, b"tesT", None));

        // signingCertificateV2 binds them to the signer's certificate.
        let attribute = Asn1Node::parse(signer.signed(oids::SIGNING_CERTIFICATE_V2)).unwrap();
        let cert_id = attribute.child(0).unwrap().child(0).unwrap();
        let cert_hash_oid = cert_id.child(0).unwrap().child(0).unwrap().to_oid().unwrap();
        assert_eq!(
            cert_id.child(1).unwrap().to_octet_string().unwrap(),
            recipes::hash(&cert_hash_oid, certificate, None)
        );

        // The signature covers the DER signed attributes; the field holds D (64 bytes for m = 257, little-endian).
        let mut attributes_hash = recipes::hash(hash_oid, &signer.signed_attributes, None);
        assert_eq!(signer.signature.len(), 64);
        assert!(recipes::verify_dstu4145(&key, &attributes_hash, &signer.signature));
        assert!(recipes::verify_cms_signer(signer, certificate));
        attributes_hash[0] ^= 1;
        assert!(!recipes::verify_dstu4145(&key, &attributes_hash, &signer.signature));
    }
}

#[test]
fn the_signer_certificate_chains_to_the_root() {
    let pki = Hierarchy::shared();
    let (cms, _) = create(oids::DSTU7564_256, true, "b", false);
    let pool: Vec<Vec<u8>> = pki
        .validation_certificates()
        .iter()
        .map(|c| c.encoded().to_vec())
        .collect();
    let root = vec![pki.root.certificate.encoded().to_vec()];
    assert!(recipes::chains_to_trusted(&cms.certificates[0], &pool, &root));
}

#[test]
fn an_asic_s_container_is_well_formed_and_its_signature_verifies() {
    // ASiC-S (ETSI EN 319 162): mimetype first and uncompressed, one data file and META-INF/signature.p7s, a detached
    // CAdES-T signature with time-stamps on both the data and the signature.
    let entries = read_zip(&read_oracle("cades/asics-gost34311-t-content-ts.asics"));
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["mimetype", "data.txt", asic_container::ASIC_S_SIGNATURE_ENTRY]);
    assert!(entries[0].is_stored);
    assert_eq!(entries[0].content, asic_container::ASIC_S_MIME_TYPE.as_bytes());

    let cms = recipes::read_cms(&entries[2].content);
    assert!(cms.content.is_none());
    let signer = &cms.signers[0];
    assert_eq!(
        signer.message_digest(),
        recipes::hash(oids::GOST34311, &entries[1].content, None)
    );
    assert!(recipes::verify_cms_signer(signer, &cms.certificates[0]));
}

#[test]
fn time_stamps_cover_the_data_and_the_signature() {
    // The signed attribute contentTimeStamp covers the data, the unsigned signatureTimeStampToken the signature value.
    let pki = Hierarchy::shared();
    for hash_oid in [oids::DSTU7564_256, oids::GOST34311] {
        let (cms, data) = create(hash_oid, true, "t", true);
        let signer = &cms.signers[0];
        let content_token = signer.signed(oids::CONTENT_TIME_STAMP);
        assert!(recipes::imprint_covers(content_token, &data));
        let signature_token = signer.unsigned(oids::SIGNATURE_TIME_STAMP_TOKEN);
        let (imprint_algorithm, _, _) = recipes::read_time_stamp(signature_token);
        assert_eq!(imprint_algorithm, hash_oid);
        assert!(recipes::imprint_covers(signature_token, &signer.signature));
        for token in [content_token, signature_token] {
            let token = recipes::read_cms(token);
            assert_eq!(token.certificates, [pki.tsa.certificate.encoded().to_vec()]);
            assert!(recipes::verify_cms_signer(
                &token.signers[0],
                pki.tsa.certificate.encoded()
            ));
        }
    }
}

#[test]
fn long_term_validation_data_is_consistent() {
    // CAdES-X Long: the references match the values, the CA among them verifies the signer's certificate, and every
    // OCSP response is signed by its responder and says "good".
    let (cms, _) = create(oids::DSTU7564_256, true, "x-long", false);
    let signer = &cms.signers[0];
    let certificate = &cms.certificates[0];
    let values = Asn1Node::parse(signer.unsigned(oids::CERT_VALUES)).unwrap();
    let certificates: Vec<Vec<u8>> = values
        .children()
        .unwrap()
        .iter()
        .map(|c| c.encoded().to_vec())
        .collect();
    let references = Asn1Node::parse(signer.unsigned(oids::CERTIFICATE_REFS))
        .unwrap()
        .children()
        .unwrap();
    assert_eq!(certificates.len(), references.len());
    for reference in &references {
        let other_hash = reference.child(0).unwrap();
        let algorithm = other_hash.child(0).unwrap().child(0).unwrap().to_oid().unwrap();
        let value = other_hash.child(1).unwrap().to_octet_string().unwrap();
        assert!(certificates.iter().any(|c| recipes::hash(&algorithm, c, None) == value));
    }
    let issuer_name = recipes::names(certificate).1;
    let ca: Vec<&Vec<u8>> = certificates
        .iter()
        .filter(|c| recipes::names(c).0 == issuer_name)
        .collect();
    assert_eq!(ca.len(), 1);
    assert!(recipes::verify_certificate(certificate, ca[0]));

    let revocation_values = Asn1Node::parse(signer.unsigned(oids::REVOCATION_VALUES)).unwrap();
    let responses = revocation_values
        .child(0)
        .unwrap()
        .child(0)
        .unwrap()
        .children()
        .unwrap();
    let revocation_refs = Asn1Node::parse(signer.unsigned(oids::REVOCATION_REFS)).unwrap();
    let identifiers = revocation_refs
        .child(0)
        .unwrap()
        .child(0)
        .unwrap()
        .child(0)
        .unwrap()
        .child(0)
        .unwrap()
        .children()
        .unwrap();
    assert!(!responses.is_empty());
    assert_eq!(responses.len(), identifiers.len());
    for identifier in &identifiers {
        let other_hash = identifier.child(1).unwrap();
        let algorithm = other_hash.child(0).unwrap().child(0).unwrap().to_oid().unwrap();
        let value = other_hash.child(1).unwrap().to_octet_string().unwrap();
        assert!(
            responses
                .iter()
                .any(|r| recipes::hash(&algorithm, r.encoded(), None) == value)
        );
    }

    let mut known = certificates.clone();
    known.push(certificate.clone());
    let mut covered = Vec::new();
    for response in &responses {
        let responder = recipes::find_ocsp_responder(response.encoded(), &known);
        assert!(recipes::verify_ocsp(response.encoded(), &responder));
        let statuses = recipes::ocsp_statuses(response.encoded());
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].1, 0); // good
        let about: Vec<&Vec<u8>> = known
            .iter()
            .filter(|c| recipes::serial_number(c) == statuses[0].0)
            .collect();
        assert_eq!(about.len(), 1);
        covered.push(about[0].clone());
    }
    assert!(covered.contains(certificate));
    assert!(covered.contains(ca[0]));
}

#[test]
fn tampered_data_fails_the_message_digest() {
    let (cms, _) = create(oids::DSTU7564_256, true, "b", false);
    assert_ne!(
        cms.signers[0].message_digest(),
        recipes::hash(oids::DSTU7564_256, b"tesT", None)
    );
}

#[test]
fn a_foreign_certificate_fails_the_signing_certificate_check() {
    let (cms, _) = create(oids::DSTU7564_256, true, "b", false);
    assert!(!recipes::verify_cms_signer(
        &cms.signers[0],
        Hierarchy::shared().issuing_ca.certificate.encoded()
    ));
}
