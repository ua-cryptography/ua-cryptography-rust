//! The HTTP clients against a local server that reads the requests with `ua-der`: RFC 3161 with nonce and certReq,
//! OCSP with CertID and nonce, caIssuers bundles, and the error paths. The requests themselves are compared with
//! those the C# package made (`tsp/tsp.json`, `ocsp/ocsp.json`).

mod common;

use std::sync::atomic::Ordering;

use common::local_server::LocalPkiServer;
use common::{Hierarchy, hex, read_json, read_oracle, stamp_hash, to_hex};
use num_bigint::BigInt;
use ua_pki::{
    CertificateSource, HttpCertificateSource, HttpOcspService, HttpTimeStampService, OcspCertificateStatus,
    OcspResponse, OcspService, ServiceError, TimeStampError, TimeStampService, algorithms, oids, time_stamp_protocol,
};

#[test]
fn the_time_stamping_service_answers_the_request() {
    let pki = Hierarchy::shared();
    for hash_oid in [oids::DSTU7564_256, oids::GOST34311] {
        let server = LocalPkiServer::start(Vec::new());
        let hash = algorithms::hash(hash_oid, b"covered", None).unwrap();
        let token = HttpTimeStampService::new(&server.tsa_url())
            .get_token(&hash, hash_oid)
            .unwrap();
        assert_eq!(token.imprint(), hash.as_slice());
        assert_eq!(token.imprint_algorithm(), hash_oid);
        assert!(token.nonce().is_some());
        assert_eq!(token.cms().certificates(), std::slice::from_ref(&pki.tsa.certificate)); // certReq honoured
        assert_eq!(server.counters.time_stamps.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn requests_are_written_as_the_csharp_package_writes_them() {
    for request in read_json("tsp/tsp.json")["requests"].as_array().unwrap() {
        let input = &request["input"];
        let nonce: BigInt = input["nonce"].as_str().unwrap().parse().unwrap();
        let written = time_stamp_protocol::create_request(
            &hex(input["hash"].as_str().unwrap()),
            input["hashOid"].as_str().unwrap(),
            &nonce,
            None,
        );
        assert_eq!(written, read_oracle(request["file"].as_str().unwrap()));
    }
    let pki = Hierarchy::shared();
    for request in read_json("ocsp/ocsp.json")["requests"].as_array().unwrap() {
        let input = &request["input"];
        let written = OcspResponse::create_request(
            &pki.signer.certificate,
            &pki.issuing_ca.certificate,
            input["hashOid"].as_str().unwrap(),
            &hex(input["nonce"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            to_hex(&written),
            to_hex(&read_oracle(request["file"].as_str().unwrap()))
        );
    }
}

#[test]
fn forged_time_stamp_responses_are_refused() {
    let hash = [0u8; 32];
    let nonce = time_stamp_protocol::create_nonce();
    let token = stamp_hash(&hash, oids::DSTU7564_256, true, Some(&nonce));
    let response = ua_der::sequence([ua_der::sequence([ua_der::integer_from_i64(0)]), token]);

    assert!(time_stamp_protocol::parse_response(&response, &hash, oids::DSTU7564_256, &nonce).is_ok());
    let other = time_stamp_protocol::parse_response(&response, &[1u8; 32], oids::DSTU7564_256, &nonce);
    assert_eq!(other.unwrap_err(), TimeStampError::OtherImprint);
    let other = time_stamp_protocol::parse_response(&response, &hash, oids::DSTU7564_256, &(&nonce + 1));
    assert_eq!(other.unwrap_err(), TimeStampError::OtherNonce);
    let refused = ua_der::sequence([ua_der::sequence([ua_der::integer_from_i64(2)])]);
    let refusal = time_stamp_protocol::parse_response(&refused, &hash, oids::DSTU7564_256, &nonce).unwrap_err();
    assert!(matches!(refusal, TimeStampError::Refused { status: 2, .. }));

    // The responses the C# LocalPkiServer wrote.
    let recorded = read_json("tsp/tsp.json");
    let granted = &recorded["responses"][0];
    let nonce: BigInt = granted["nonce"].as_str().unwrap().parse().unwrap();
    let response = read_oracle(granted["file"].as_str().unwrap());
    let token = time_stamp_protocol::parse_response(&response, &hash, oids::DSTU7564_256, &nonce).unwrap();
    assert_eq!(token.nonce(), Some(&nonce));
    let refusal = time_stamp_protocol::parse_response(
        &read_oracle("tsp/response-rejection.der"),
        &hash,
        oids::DSTU7564_256,
        &nonce,
    );
    assert!(matches!(
        refusal.unwrap_err(),
        TimeStampError::Refused { status: 2, .. }
    ));
}

#[test]
fn the_ocsp_service_answers_about_the_certificate() {
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start(Vec::new());
    let signer = &pki.signer.certificate;
    let ca = &pki.issuing_ca.certificate;
    let response = HttpOcspService::new(Some(&server.ocsp_url()))
        .find_response(signer, ca, oids::DSTU7564_256)
        .unwrap()
        .unwrap();
    assert_eq!(response.find(signer, ca).unwrap().status, OcspCertificateStatus::Good);
    assert!(response.is_signed_by(&response.find_responder(&[]).unwrap()));
    assert_eq!(server.counters.ocsp.load(Ordering::SeqCst), 1);

    // No responder named in the certificate and none given: nothing to ask.
    assert_eq!(
        HttpOcspService::new(None)
            .find_response(signer, ca, oids::DSTU7564_256)
            .unwrap(),
        None
    );
}

#[test]
fn a_ca_issuers_bundle_is_downloaded() {
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start(Vec::new());
    let certificates = HttpCertificateSource::new()
        .download_certificates(&server.ca_issuers_url())
        .unwrap();
    assert_eq!(certificates.len(), 3);
    for expected in [&pki.issuing_ca, &pki.tsa, &pki.ocsp] {
        assert!(certificates.contains(&expected.certificate));
    }
    assert_eq!(server.counters.ca_issuers.load(Ordering::SeqCst), 1);
}

#[test]
fn http_errors_and_oversized_answers_are_service_errors() {
    let server = LocalPkiServer::start(Vec::new());
    let missing = format!("{}/missing", server.base_url);
    let refusal = HttpTimeStampService::new(&missing)
        .get_token(&[0u8; 32], oids::DSTU7564_256)
        .unwrap_err();
    assert!(matches!(refusal, ServiceError::Status { status: 404, .. }), "{refusal}");

    let large = format!("{}/large", server.base_url);
    let refusal = HttpCertificateSource::new().download_certificates(&large).unwrap_err();
    assert!(matches!(refusal, ServiceError::TooLarge { .. }), "{refusal}");
}
