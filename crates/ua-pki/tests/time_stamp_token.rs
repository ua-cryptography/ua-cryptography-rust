//! RFC 3161 tokens of the hierarchy's TSA (the C# one, recorded, and the in-process Rust one) read by the crate: the
//! imprint, the service certificate found with or without embedding, and a token over other data refused inside a
//! CAdES signature.

mod common;

use common::{Hierarchy, TestTimeStamps, describe, has_check, read_oracle, stamp};
use ua_pki::{
    CadesOptions, CadesSigner, CheckStatus, SignatureLevel, SignatureServices, TimeStampToken, ValidationOptions,
    VerificationReport, cades_verifier, cms_builder, oids,
};

const COVERED: &[u8] = b"covered bytes";

#[test]
fn a_token_covers_its_data_only() {
    let pki = Hierarchy::shared();
    for (hash_oid, fixture) in [
        (oids::DSTU7564_256, "tsp/token-dstu7564.der"),
        (oids::GOST34311, "tsp/token-gost34311.der"),
    ] {
        assert_eq!(read_oracle("tsp/covered.bin"), COVERED);
        for der in [read_oracle(fixture), stamp(COVERED, hash_oid, true)] {
            let token = TimeStampToken::load(&der).unwrap();
            assert_eq!(token.imprint_algorithm(), hash_oid);
            assert_eq!(token.policy(), common::policy_for(hash_oid));
            assert!(token.covers(COVERED));
            assert!(!token.covers(b"covered bytes\0"));

            let mut report = VerificationReport::new("token");
            let authority = token.verify(COVERED, &[], &mut report, "ts");
            assert_eq!(authority, Some(pki.tsa.certificate.clone()));
            assert!(report.is_valid(), "{:?}", report.checks);

            let mut report = VerificationReport::new("token");
            token.verify(b"other bytes", &[], &mut report, "ts");
            assert!(has_check(&report, "ts: imprint", CheckStatus::Failed));
        }
    }
}

#[test]
fn the_service_certificate_is_found_among_known_ones_when_not_embedded() {
    let pki = Hierarchy::shared();
    for der in [
        read_oracle("tsp/token-gost34311-no-certificate.der"),
        stamp(COVERED, oids::GOST34311, false),
    ] {
        let token = TimeStampToken::load(&der).unwrap();
        assert!(token.find_signer_certificate(&[]).is_none());
        assert_eq!(
            token.find_signer_certificate(&pki.all_certificates()),
            Some(pki.tsa.certificate.clone())
        );

        let mut report = VerificationReport::new("token");
        assert!(token.verify(COVERED, &[], &mut report, "ts").is_none());
        assert!(has_check(&report, "ts: service certificate", CheckStatus::Warning));
    }
}

#[test]
fn a_signature_time_stamp_over_other_bytes_fails_the_signature() {
    let pki = Hierarchy::shared();
    let signer = pki.signing_key();
    let data = read_oracle("tsp/data.bin");
    assert_eq!(data, b"data");
    let attributes = cms_builder::signed_attributes(&data, oids::DATA, &signer, oids::DSTU7564_256, &[]).unwrap();
    let (_, signature) = cms_builder::signer_info(&attributes, &signer, oids::DSTU7564_256, &[]).unwrap();

    // A genuine token of the TSA, but over the data instead of the signature value.
    for wrong_token in [
        read_oracle("tsp/token-dstu7564-over-data.der"),
        stamp(&data, oids::DSTU7564_256, true),
    ] {
        let unsigned = [cms_builder::attribute(oids::SIGNATURE_TIME_STAMP_TOKEN, [wrong_token])];
        let signer_info = cms_builder::signer_info_with(
            &attributes,
            &signature,
            signer.certificate(),
            oids::DSTU7564_256,
            &unsigned,
        )
        .unwrap();
        let certificates = [signer.certificate().clone()];
        let cms = cms_builder::signed_data(&signer_info, oids::DSTU7564_256, oids::DATA, Some(&data), &certificates);

        let options = ValidationOptions {
            extra_certificates: pki.all_certificates(),
            ..ValidationOptions::default()
        };
        let result = cades_verifier::verify(&cms, None, &options).unwrap();
        assert!(!result.is_valid());
        let report = &result.signatures[0];
        assert!(has_check(report, "signature time-stamp: imprint", CheckStatus::Failed));
        assert_eq!(report.time_stamp_time, None);
    }

    // The same signer with a correct token is valid.
    let time_stamps = TestTimeStamps::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ..SignatureServices::default()
    };
    let options = CadesOptions {
        level: SignatureLevel::T,
        ..CadesOptions::default()
    };
    let good = CadesSigner::new(signer, services).sign(&data, &options).unwrap();
    let options = ValidationOptions {
        extra_certificates: pki.all_certificates(),
        ..ValidationOptions::default()
    };
    let result = cades_verifier::verify(&good, None, &options).unwrap();
    assert!(result.is_valid(), "{}", describe(&result));
}
