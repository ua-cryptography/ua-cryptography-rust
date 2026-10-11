//! The two provider formats of docs/provider-formats.md end to end through ua-sign with keys in JKS: for each, a
//! signature made by ua-sign has the provider's profile (checked by the independent recipes) and verifies, and a
//! signature made the way the provider makes it (recorded by the C# oracle) verifies too. The services — TSA, OCSP,
//! the caIssuers bundle — are the local PKI server.

mod common;

use common::local_server::LocalPkiServer;
use common::profiles::{assert_diia_profile, assert_privatbank_profile};
use common::{
    Hierarchy, TestDirectory, issue, oracle_certificate, position_of, read_oracle, read_zip, run, write_key_store,
    write_zip,
};
use ua_cryptography_pki::{Certificate, Dstu4145PrivateKey};
use ua_cryptography_sign::{EXIT_INVALID, EXIT_VALID};

const PASSWORD: &str = "provider formats";
const DOCUMENT: &str = "Документ для підпису\n";
/// The address the recorded PrivatBank customer certificate names for its OCSP responder and caIssuers bundle.
const RECORDED_BANK_ADDRESS: &str = "127.0.0.1:18089";

/// A customer's certificate as a bank issues it: by the hierarchy's issuing CA, for the hierarchy signer's key, naming
/// the server's OCSP responder and caIssuers bundle.
fn bank_customer(pki: &Hierarchy, server: &LocalPkiServer) -> Certificate {
    let customer = issue(
        "CN=Test Bank Customer,O=UA Cryptography Tests,C=UA",
        &pki.signer.key,
        &pki.issuing_ca,
        Some(&server.ocsp_url()),
        Some(&server.ca_issuers_url()),
    );
    server.add_certificate(customer.clone());
    customer
}

fn privatbank_sig_is_made_by_ua_sign_and_verifies(is_bank_issued: bool) {
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start();
    let directory = TestDirectory::new("provider-formats");
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let keystore = directory.path("key.jks");
    let root = pki.write_root(&directory.path("root.cer"));
    let (signer, trust) = if is_bank_issued {
        // The key store as PrivatBank issues it: the chain root first, then the certificate of the key-agreement key.
        let customer = bank_customer(pki, &server);
        let agreement_key = Dstu4145PrivateKey::generate(&ua_cryptography_dstu4145::get_polynomial_curve(431).unwrap());
        let agreement = issue(
            "CN=Test Bank Customer,O=UA Cryptography Tests,C=UA",
            &agreement_key,
            &pki.issuing_ca,
            None,
            None,
        );
        let chain = vec![
            pki.root.certificate.clone(),
            pki.issuing_ca.certificate.clone(),
            customer.clone(),
            agreement,
        ];
        write_key_store(&keystore, "pb_sign", &pki.signer.key, chain, PASSWORD);
        (customer, vec!["--trust".to_owned(), root, "--online".to_owned()])
    } else {
        let certificate = directory.path("key.cer");
        let (code, output) = run(&[
            "keygen",
            "--keystore",
            &keystore,
            "--subject",
            "CN=Keygen Signer,O=UA Cryptography Tests,C=UA",
            "--password",
            PASSWORD,
            "--cert",
            &certificate,
        ]);
        assert_eq!(code, EXIT_VALID, "{output}");
        let signer = Certificate::load(&std::fs::read(&certificate).unwrap()).unwrap();
        // The key's own certificate for the signer, the hierarchy's root for the time-stamping service.
        (
            signer,
            vec!["--trust".to_owned(), certificate, "--trust".to_owned(), root],
        )
    };

    let sig = directory.path("doc.txt.sig");
    let (code, output) = run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        "cades",
        "--level",
        "T",
        "--in",
        &document,
        "--out",
        &sig,
        "--tsa",
        &server.tsa_url(),
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert_privatbank_profile(&std::fs::read(&sig).unwrap(), DOCUMENT.as_bytes(), &signer);

    let mut args = vec!["verify", "--in", &sig];
    args.extend(trust.iter().map(String::as_str));
    let (code, output) = run(&args);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(!output.contains("[FAIL]"), "{output}");
    assert!(output.contains("[ OK ] signature time-stamp: signature"), "{output}");
    assert!(output.contains("and so do its issuer and serial number"), "{output}");
    if is_bank_issued {
        assert!(
            output.contains("[ OK ] signer: revocation of 'Test Bank Customer': good, online response"),
            "{output}"
        );
    }
}

#[test]
fn a_privatbank_sig_is_made_by_ua_sign_with_a_bank_issued_key_and_verifies() {
    privatbank_sig_is_made_by_ua_sign_and_verifies(true);
}

#[test]
fn a_privatbank_sig_is_made_by_ua_sign_with_a_keygen_key_and_verifies() {
    privatbank_sig_is_made_by_ua_sign_and_verifies(false);
}

// The recorded customer certificate names the services on a fixed port, which this test serves.
#[test]
fn a_privatbank_sig_as_the_bank_makes_it_verifies() {
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start_on(RECORDED_BANK_ADDRESS);
    server.add_certificate(oracle_certificate("providers/privatbank/customer.cer"));
    let directory = TestDirectory::new("provider-formats");
    let signature = read_oracle("providers/privatbank/doc.txt.sig");
    let customer = oracle_certificate("providers/privatbank/customer.cer");
    assert_privatbank_profile(&signature, DOCUMENT.as_bytes(), &customer);
    let sig = directory.write("doc.txt.sig", &signature);

    // Offline: neither the CA's nor the TSA's certificate is in the signature.
    let (code, output) = run(&["verify", "--in", &sig]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(
        output.contains("[WARN] signature time-stamp: service certificate"),
        "{output}"
    );
    assert!(output.contains("Hint: certificates are missing"), "{output}");
    let root = pki.write_root(&directory.path("root.cer"));
    let (code, output) = run(&["verify", "--in", &sig, "--trust", &root]);
    assert_eq!(code, EXIT_INVALID, "{output}");
    assert!(output.contains("[FAIL] signer: trust"), "{output}");

    // Online: the caIssuers bundle completes both, in one download; OCSP answers for the customer.
    let (code, output) = run(&["verify", "--in", &sig, "--trust", &root, "--online"]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(!output.contains("[FAIL]"), "{output}");
    assert!(output.contains("[ OK ] signature time-stamp: signature"), "{output}");
    assert!(output.contains("[ OK ] signer: trust"), "{output}");
    assert!(
        output.contains("[ OK ] signer: revocation of 'Test Bank Customer': good"),
        "{output}"
    );
    assert_eq!(server.ca_issuers_requests(), 1);

    // The document inside is changed: invalid.
    let mut tampered = signature.clone();
    let at = position_of(&tampered, DOCUMENT.as_bytes());
    tampered[at] ^= 1;
    let tampered = directory.write("tampered.sig", &tampered);
    assert_eq!(
        run(&["verify", "--in", &tampered, "--trust", &root, "--online"]).0,
        EXIT_INVALID
    );
}

#[test]
fn a_diia_asic_e_is_made_by_ua_sign_and_verifies() {
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start();
    let directory = TestDirectory::new("provider-formats");
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let keystore = directory.path("key.jks");
    pki.write_signer_key_store(&keystore, PASSWORD);

    let container = directory.path("doc.txt.asice");
    let (code, output) = run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        "asic-e",
        "--level",
        "LT",
        "--in",
        &document,
        "--out",
        &container,
        "--tsa",
        &server.tsa_url(),
        "--ocsp",
        &server.ocsp_url(),
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert_diia_profile(
        &std::fs::read(&container).unwrap(),
        "doc.txt",
        DOCUMENT.as_bytes(),
        &pki.signer.certificate,
        &pki.issuing_ca.certificate,
    );

    // Offline, with the root only: everything the check needs is in the container.
    let root = pki.write_root(&directory.path("root.cer"));
    let (code, output) = run(&["verify", "--in", &container, "--trust", &root]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(!output.contains("[FAIL]"), "{output}");
    assert!(output.contains("XAdES-B-LT, detached, DSTU 7564-256"), "{output}");
    assert!(
        output.contains("[ OK ] signer: revocation of 'Test Signer': good, embedded"),
        "{output}"
    );
    assert!(
        output.contains("[ OK ] signer: revocation of 'Test Issuing CA': good, embedded"),
        "{output}"
    );
}

#[test]
fn a_diia_asic_e_as_diia_makes_it_verifies() {
    let pki = Hierarchy::shared();
    let directory = TestDirectory::new("provider-formats");
    let recorded = read_oracle("providers/diia/doc.txt.asice");
    assert_diia_profile(
        &recorded,
        "doc.txt",
        DOCUMENT.as_bytes(),
        &pki.signer.certificate,
        &pki.issuing_ca.certificate,
    );
    let container = directory.write("doc.txt.asice", &recorded);

    let root = pki.write_root(&directory.path("root.cer"));
    let (code, output) = run(&["verify", "--in", &container, "--trust", &root]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(!output.contains("[FAIL]"), "{output}");
    assert!(output.contains("[ OK ] manifest: lists all 1 data files"), "{output}");
    assert!(output.contains("[ OK ] signature time-stamp: signature"), "{output}");
    // The response with a zero issuerKeyHash counts; "Дія" embeds none about its CA.
    assert!(
        output.contains("[ OK ] signer: revocation of 'Test Signer': good, embedded"),
        "{output}"
    );
    assert!(
        output.contains("[WARN] signer: revocation of 'Test Issuing CA'"),
        "{output}"
    );

    // The document in the container is changed: invalid.
    let entries = read_zip(&recorded);
    let rewritten: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|entry| {
            let content = if entry.name == "doc.txt" {
                "Інший документ\n".as_bytes()
            } else {
                entry.content.as_slice()
            };
            (entry.name.as_str(), content)
        })
        .collect();
    std::fs::write(&container, write_zip(&rewritten)).unwrap();
    let (code, output) = run(&["verify", "--in", &container, "--trust", &root]);
    assert_eq!(code, EXIT_INVALID, "{output}");
    assert!(output.contains("[FAIL] reference 'doc.txt'"), "{output}");
}
