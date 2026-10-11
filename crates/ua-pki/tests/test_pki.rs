//! The synthetic PKI every signature test is built on: certificates the crate issues, the hierarchy of the fixtures,
//! time-stamp tokens and OCSP responses — those of the C# test services (recorded) and those of the in-process Rust
//! services of `tests/common` — each checked with the independent recipes.

mod common;

use common::{Hierarchy, hex, oracle_certificate, read_json, read_oracle, recipes, respond, stamp, to_hex};
use num_bigint::BigInt;
use rand_core::{OsRng, RngCore};
use ua_pki::{CertificateBuilder, DistinguishedName, Dstu4145PrivateKey, OcspResponse, TimeStampToken, oids};

fn self_signed(subject: &str, signature_algorithm: &str) -> (ua_pki::Certificate, Dstu4145PrivateKey) {
    let key = Dstu4145PrivateKey::generate(&ua_dstu4145::get_polynomial_curve(257).unwrap());
    let mut builder =
        CertificateBuilder::new(DistinguishedName::parse(subject).unwrap(), key.public_key().clone()).unwrap();
    builder.signature_algorithm = signature_algorithm.to_owned();
    let certificate = builder.add_basic_constraints(true).self_sign(&key).unwrap();
    (certificate, key)
}

#[test]
fn a_self_signed_certificate_carries_the_key_and_verifies() {
    let (root, key) = self_signed("CN=Standalone Root,C=UA", oids::DSTU4145_WITH_GOST34311);
    let read = recipes::read_public_key(root.encoded());
    assert_eq!(read.domain.field().m(), 257);
    assert_eq!(&read.q, key.public_key().q());
    assert_eq!(read.dke.as_deref(), key.dke());
    assert!(recipes::verify_certificate(root.encoded(), root.encoded()));
}

#[test]
fn an_issued_certificate_verifies_with_the_issuer_key_only() {
    for signature_algorithm in [oids::DSTU4145_WITH_GOST34311, oids::DSTU4145_WITH_DSTU7564] {
        let (root, root_key) = self_signed("CN=Root,C=UA", signature_algorithm);
        let leaf_key = Dstu4145PrivateKey::generate(&ua_dstu4145::get_polynomial_curve(257).unwrap());
        let mut builder = CertificateBuilder::new(
            DistinguishedName::parse("CN=Leaf,C=UA").unwrap(),
            leaf_key.public_key().clone(),
        )
        .unwrap();
        builder.signature_algorithm = signature_algorithm.to_owned();
        let leaf = builder.issue(&root, &root_key).unwrap();
        assert_eq!(leaf.signature_algorithm(), signature_algorithm);
        assert!(recipes::verify_certificate(leaf.encoded(), root.encoded()));
        let (other_root, _) = self_signed("CN=Root,C=UA", oids::DSTU4145_WITH_GOST34311);
        assert!(!recipes::verify_certificate(leaf.encoded(), other_root.encoded()));
    }
}

#[test]
fn the_hierarchy_mirrors_the_national_chain() {
    let pki = Hierarchy::shared();
    assert_eq!(pki.root.key.domain().field().m(), 431);
    assert_eq!(pki.signer.key.domain().field().m(), 257);
    let all: Vec<Vec<u8>> = pki.all_certificates().iter().map(|c| c.encoded().to_vec()).collect();
    let root = vec![pki.root.certificate.encoded().to_vec()];
    for certificate in &all {
        assert!(recipes::chains_to_trusted(certificate, &all, &root));
    }
    for certificate in pki.all_certificates() {
        assert_eq!(certificate.signature_algorithm(), oids::DSTU4145_WITH_DSTU7564);
    }
    // keys.json describes the same keys as the certificates hold.
    let keys = read_json("hierarchy/keys.json");
    for (name, identity) in [("root", &pki.root), ("signer", &pki.signer), ("tsa", &pki.tsa)] {
        let key = &keys["identities"][name]["key"];
        assert_eq!(
            to_hex(&identity.key.public_key().q().x().unwrap().to_bytes()).trim_start_matches('0'),
            key["qx"].as_str().unwrap().trim_start_matches('0')
        );
        assert_eq!(
            identity.certificate.public_key().unwrap().q(),
            identity.key.public_key().q()
        );
    }
}

#[test]
fn time_stamp_tokens_cover_their_data_and_are_signed_by_the_tsa() {
    let pki = Hierarchy::shared();
    for hash_oid in [oids::DSTU7564_256, oids::GOST34311] {
        let mut data = [0u8; 100];
        OsRng.fill_bytes(&mut data);
        let token = stamp(&data, hash_oid, true);
        let (algorithm, _, policy) = recipes::read_time_stamp(&token);
        assert_eq!(algorithm, hash_oid);
        assert_eq!(policy, common::policy_for(hash_oid));
        assert!(recipes::imprint_covers(&token, &data));
        let mut longer = data.to_vec();
        longer.push(0);
        assert!(!recipes::imprint_covers(&token, &longer));

        let cms = recipes::read_cms(&token);
        assert_eq!(cms.certificates, [pki.tsa.certificate.encoded().to_vec()]);
        assert!(recipes::verify_cms_signer(
            &cms.signers[0],
            pki.tsa.certificate.encoded()
        ));
    }

    // The C# TSA's tokens pass the same recipes.
    for token in read_json("tsp/tsp.json")["tokens"].as_array().unwrap() {
        let file = token["file"].as_str().unwrap();
        let der = read_oracle(file);
        let covered = read_oracle(token["covered"].as_str().unwrap());
        assert!(recipes::imprint_covers(&der, &covered), "{file}");
        let cms = recipes::read_cms(&der);
        assert!(
            recipes::verify_cms_signer(&cms.signers[0], pki.tsa.certificate.encoded()),
            "{file}"
        );
        let parsed = TimeStampToken::load(&der).unwrap();
        assert_eq!(to_hex(parsed.imprint()), token["imprint"].as_str().unwrap(), "{file}");
        assert_eq!(parsed.policy(), token["policy"].as_str().unwrap(), "{file}");
        assert_eq!(
            parsed.serial_number().to_string(),
            token["serialNumber"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            parsed.signer().digest_algorithm(),
            token["signerDigestAlgorithm"].as_str().unwrap()
        );
        assert_eq!(
            parsed.signer().signature_algorithm(),
            token["signerSignatureAlgorithm"].as_str().unwrap()
        );
        assert_eq!(
            parsed.cms().certificates().len() == 1,
            token["tsaCertificateEmbedded"].as_bool().unwrap()
        );
        assert!(parsed.nonce().is_none());
    }
}

#[test]
fn the_time_stamp_signer_is_found_by_issuer_and_serial_when_not_embedded() {
    let pki = Hierarchy::shared();
    let rust_made = stamp(&[1, 2, 3], oids::GOST34311, false);
    for der in [rust_made, read_oracle("tsp/token-gost34311-no-certificate.der")] {
        let token = TimeStampToken::load(&der).unwrap();
        assert!(token.find_signer_certificate(&[]).is_none());
        assert_eq!(
            token.find_signer_certificate(&pki.validation_certificates()),
            Some(pki.tsa.certificate.clone())
        );
    }
}

#[test]
fn an_ocsp_response_is_signed_by_the_responder_and_good() {
    let pki = Hierarchy::shared();
    let rust_made = respond(&pki.ocsp, &pki.signer.certificate, &pki.issuing_ca.certificate, false);
    for full in [rust_made, read_oracle("hierarchy/ocsp-signer.der")] {
        let basic = recipes::read_ocsp_response(&full);
        let responder = recipes::find_ocsp_responder(&basic, &[]);
        assert_eq!(responder, pki.ocsp.certificate.encoded());
        assert!(recipes::verify_ocsp(&basic, &responder));
        assert!(!recipes::verify_ocsp(&basic, pki.root_ocsp.certificate.encoded()));
        let statuses = recipes::ocsp_statuses(&basic);
        assert_eq!(statuses, [(pki.signer.certificate.serial_number().clone(), 0)]);

        // The full OCSPResponse round-trips through the crate.
        let response = OcspResponse::load(&full).unwrap();
        assert_eq!(response.basic_encoded(), basic.as_slice());
        assert_eq!(recipes::read_ocsp_response(&response.full_encoded()), basic);
    }
}

#[test]
fn ocsp_responses_read_as_bouncy_castle_reads_them() {
    for expected in read_json("ocsp/ocsp.json")["responses"].as_array().unwrap() {
        let file = expected["file"].as_str().unwrap();
        let response = OcspResponse::load(&read_oracle(file)).unwrap();
        assert_eq!(
            to_hex(response.responder_name().unwrap().encoded()),
            expected["responderName"].as_str().unwrap()
        );
        assert_eq!(
            to_hex(response.tbs_response_data()),
            expected["tbsResponseData"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            to_hex(response.signature_value()),
            expected["signatureBitString"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            response.signature_algorithm(),
            expected["signatureAlgorithm"].as_str().unwrap()
        );
        assert_eq!(
            response.certificates().len() as u64,
            expected["certificates"].as_u64().unwrap()
        );
        let single = &response.responses()[0];
        let expected_single = &expected["responses"][0];
        assert_eq!(
            single.hash_algorithm,
            expected_single["hashAlgorithm"].as_str().unwrap()
        );
        assert_eq!(
            single.issuer_name_hash,
            hex(expected_single["issuerNameHash"].as_str().unwrap())
        );
        assert_eq!(
            single.issuer_key_hash,
            hex(expected_single["issuerKeyHash"].as_str().unwrap())
        );
        let serial: BigInt = expected_single["serialNumber"].as_str().unwrap().parse().unwrap();
        assert_eq!(single.serial_number, serial);
        assert_eq!(single.status, ua_pki::OcspCertificateStatus::Good);
        let responder = oracle_certificate(expected["responderCertificate"].as_str().unwrap());
        assert!(response.is_signed_by(&responder), "{file}");
    }
}
