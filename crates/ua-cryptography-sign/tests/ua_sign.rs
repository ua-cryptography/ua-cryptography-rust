//! The ua-sign command line end to end, in process: key generation, signing in every format and level, verification
//! with its exit codes, and the usage errors. Levels T and LT go through HTTP to the local PKI server.

mod common;

use std::collections::BTreeMap;

use common::local_server::LocalPkiServer;
use common::{Hierarchy, TestDirectory, position_of, recipes, run, run_with_environment, testdata_path, to_hex_upper};
use ua_cryptography_pki::{JksKeyStore, SignatureLevel, SignatureServices, SignedFile, SigningKey, XadesSigner, oids};
use ua_cryptography_sign::{EXIT_ERROR, EXIT_INVALID, EXIT_VALID};

const PASSWORD: &str = "test password";
const DOCUMENT: &str = "Підписаний документ\n";

/// A key store `name` (and `name.cer`) made by `keygen` with `extra` options.
fn keygen(directory: &TestDirectory, name: &str, extra: &[&str]) -> String {
    let keystore = directory.path(name);
    let certificate = format!("{keystore}.cer");
    let mut args = vec![
        "keygen",
        "--keystore",
        &keystore,
        "--subject",
        "CN=CLI Signer,O=UA Cryptography Tests,C=UA",
        "--password",
        PASSWORD,
        "--cert",
        &certificate,
    ];
    args.extend_from_slice(extra);
    let (code, output) = run(&args);
    assert_eq!(code, EXIT_VALID, "{output}");
    keystore
}

fn sign_and_verify_each_format(format: &str, hash: &str) {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "key.jks", &[]);
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let (code, output) = run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        format,
        "--hash",
        hash,
        "--in",
        &document,
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");
    let signed: Vec<String> = directory
        .files()
        .into_iter()
        .filter(|file| *file != keystore && *file != document && !file.ends_with(".cer"))
        .collect();
    assert_eq!(signed.len(), 1, "{signed:?}");
    let signed = &signed[0];

    let trusted = format!("{keystore}.cer");
    let (code, output) = run(&["verify", "--in", signed, "--trust", &trusted]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(output.contains("Result: VALID"), "{output}");
    assert!(!output.contains("[WARN] signer: trust"), "{output}");

    // Without a trusted root the result is still valid, with a warning.
    let (code, output) = run(&["verify", "--in", signed]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(output.contains("[WARN] signer: trust"), "{output}");
}

#[test]
fn cades_with_dstu7564_is_signed_and_verified() {
    sign_and_verify_each_format("cades", "dstu7564");
}

#[test]
fn cades_with_gost34311_is_signed_and_verified() {
    sign_and_verify_each_format("cades", "gost34311");
}

#[test]
fn xades_with_dstu7564_is_signed_and_verified() {
    sign_and_verify_each_format("xades", "dstu7564");
}

#[test]
fn xades_with_gost34311_is_signed_and_verified() {
    sign_and_verify_each_format("xades", "gost34311");
}

#[test]
fn asic_s_with_dstu7564_is_signed_and_verified() {
    sign_and_verify_each_format("asic-s", "dstu7564");
}

#[test]
fn asic_e_with_dstu7564_is_signed_and_verified() {
    sign_and_verify_each_format("asic-e", "dstu7564");
}

#[test]
fn a_detached_cades_finds_its_data_and_extraction_works() {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "key.jks", &[]);
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let (code, output) = run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        "cades",
        "--detached",
        "--in",
        &document,
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");

    // doc.txt.p7s next to doc.txt: the data is found by name.
    let signature = format!("{document}.p7s");
    let (code, output) = run(&["verify", "--in", &signature, "--extract", &directory.path("out")]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert_eq!(
        std::fs::read(directory.path("out/doc.txt")).unwrap(),
        DOCUMENT.as_bytes()
    );

    // Other data given explicitly: invalid.
    let other = directory.write("other.txt", "Інший документ\n".as_bytes());
    assert_eq!(run(&["verify", "--in", &signature, "--data", &other]).0, EXIT_INVALID);
}

#[test]
fn several_files_are_signed_in_xades_and_asic_e() {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "key.jks", &[]);
    let a = directory.write("a.txt", b"A");
    let b = directory.write("b.txt", b"B");
    let both_asice = directory.path("both.asice");
    let both_xml = directory.path("both.xml");
    for (format, out) in [("asic-e", &both_asice), ("xades", &both_xml)] {
        let (code, output) = run(&[
            "sign",
            "--keystore",
            &keystore,
            "--password",
            PASSWORD,
            "--format",
            format,
            "--in",
            &a,
            "--in",
            &b,
            "--out",
            out,
        ]);
        assert_eq!(code, EXIT_VALID, "{output}");
    }

    assert_eq!(run(&["verify", "--in", &both_asice]).0, EXIT_VALID);
    // a.txt and b.txt are next to it.
    assert_eq!(run(&["verify", "--in", &both_xml]).0, EXIT_VALID);
    std::fs::write(&b, "changed").unwrap();
    let (code, output) = run(&["verify", "--in", &both_xml]);
    assert_eq!(code, EXIT_INVALID, "{output}");
    assert!(output.contains("[FAIL] reference 'b.txt'"), "{output}");
}

#[test]
fn references_outside_the_signature_directory_are_not_followed() {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "key.jks", &[]);
    let store = JksKeyStore::load(&std::fs::read(&keystore).unwrap(), PASSWORD).unwrap();
    let signer = SigningKey::from_jks(&store, PASSWORD, None, None).unwrap();
    let outside = b"outside".to_vec();
    let outside_path = directory.write("outside.txt", &outside);
    std::fs::create_dir_all(directory.path("inner")).unwrap();
    let files = [SignedFile {
        name: "../outside.txt".to_owned(),
        content: outside,
    }];
    let signature = XadesSigner::new(signer, SignatureServices::default())
        .sign_to_bytes(&files, oids::DSTU7564_256, SignatureLevel::B)
        .unwrap();
    let signature_path = directory.write("inner/sig.xml", &signature);

    let (code, output) = run(&["verify", "--in", &signature_path]);
    assert_eq!(code, EXIT_INVALID, "{output}");
    assert!(output.contains("the referenced file was not given"), "{output}");
    let (code, output) = run(&["verify", "--in", &signature_path, "--data", &outside_path]);
    assert_eq!(code, EXIT_VALID, "{output}");
}

#[test]
fn a_tampered_signature_is_invalid() {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "key.jks", &[]);
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        "cades",
        "--in",
        &document,
    ]);
    let mut signature = std::fs::read(format!("{document}.p7s")).unwrap();
    let offset = position_of(&signature, DOCUMENT.as_bytes());
    signature[offset] ^= 1;
    let tampered = directory.write("tampered.p7s", &signature);
    let (code, output) = run(&["verify", "--in", &tampered]);
    assert_eq!(code, EXIT_INVALID, "{output}");
    assert!(output.contains("Result: INVALID"), "{output}");
}

fn higher_levels_use_the_time_stamping_and_ocsp_services(format: &str, level: &str) {
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start();
    let directory = TestDirectory::new("ua-sign-tests");
    // The hierarchy's signer in a JKS, with its full chain, as a bank would issue it.
    let keystore = directory.path("signer.jks");
    pki.write_signer_key_store(&keystore, PASSWORD);
    let root = pki.write_root(&directory.path("root.cer"));
    let ca = directory.write("ca.cer", pki.issuing_ca.certificate.encoded());
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let signed = directory.path("signed");

    let (code, output) = run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        format,
        "--level",
        level,
        "--in",
        &document,
        "--out",
        &signed,
        "--tsa",
        &server.tsa_url(),
        "--ocsp",
        &server.ocsp_url(),
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(server.time_stamp_requests() >= 1);
    assert_eq!(server.ocsp_requests(), if level == "LT" { 2 } else { 0 });

    // Levels B and T carry only the signer's certificate: the CA comes from --certs.
    let (code, output) = run(&[
        "verify", "--in", &signed, "--data", &document, "--trust", &root, "--certs", &ca,
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(output.contains("Time-stamp:"), "{output}");
    if level == "LT" {
        assert!(
            output.contains("[ OK ] signer: revocation of 'Test Signer': good"),
            "{output}"
        );
        assert!(
            output.contains("[ OK ] signer: revocation of 'Test Issuing CA': good"),
            "{output}"
        );
    }
}

#[test]
fn cades_t_uses_the_time_stamping_service() {
    higher_levels_use_the_time_stamping_and_ocsp_services("cades", "T");
}

#[test]
fn cades_lt_uses_the_time_stamping_and_ocsp_services() {
    higher_levels_use_the_time_stamping_and_ocsp_services("cades", "LT");
}

#[test]
fn asic_s_lt_uses_the_time_stamping_and_ocsp_services() {
    higher_levels_use_the_time_stamping_and_ocsp_services("asic-s", "LT");
}

#[test]
fn xades_t_uses_the_time_stamping_service() {
    higher_levels_use_the_time_stamping_and_ocsp_services("xades", "T");
}

#[test]
fn asic_e_lt_uses_the_time_stamping_and_ocsp_services() {
    higher_levels_use_the_time_stamping_and_ocsp_services("asic-e", "LT");
}

type Ini = BTreeMap<String, BTreeMap<String, String>>;

fn parse_ini(text: &str) -> Ini {
    let mut sections = Ini::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
            assert!(sections.insert(name.to_owned(), BTreeMap::new()).is_none(), "{name}");
            current = Some(name.to_owned());
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("Not an INI line: {line}"));
        assert!(!key.is_empty(), "Not an INI line: {line}");
        let section = sections.get_mut(current.as_ref().unwrap()).unwrap();
        assert!(section.insert(key.to_owned(), value.to_owned()).is_none(), "{line}");
    }
    sections
}

fn sections_starting_with<'a>(ini: &'a Ini, prefix: &str) -> Vec<&'a BTreeMap<String, String>> {
    ini.iter()
        .filter(|(name, _)| name.starts_with(prefix))
        .map(|(_, section)| section)
        .collect()
}

fn ini_report_holds_every_detail(format: &str, level: &str, reference: &str) {
    let pki = Hierarchy::shared();
    let server = LocalPkiServer::start();
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = directory.path("signer.jks");
    pki.write_signer_key_store(&keystore, PASSWORD);
    let root = pki.write_root(&directory.path("root.cer"));
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let signed = directory.path("signed");
    let (code, output) = run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        format,
        "--level",
        "LT",
        "--in",
        &document,
        "--out",
        &signed,
        "--tsa",
        &server.tsa_url(),
        "--ocsp",
        &server.ocsp_url(),
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");

    let report = directory.path("report.ini");
    let (code, output) = run(&[
        "verify", "--in", &signed, "--data", &document, "--trust", &root, "--format", "ini", "--report", &report,
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");
    let ini = parse_ini(&output);

    assert_eq!(ini["summary"]["result"], "VALID");
    assert_eq!(ini["summary"]["failures"], "0");
    let signature = &ini["signature.1"];
    assert_eq!(signature["level"], level);
    assert_eq!(signature["digest_algorithm"], "DSTU 7564-256 (1.2.804.2.1.1.1.1.2.2.1)");
    assert!(signature["signature_algorithm"].starts_with("DSTU 4145 with DSTU 7564-256 ("));
    assert_eq!(signature["timestamp_time"], signature["validation_time"]);

    let signer = &pki.signer.certificate;
    let serial = format!("{:X}", signer.serial_number());
    assert_eq!(ini["signature.1.signer"]["subject"], signer.subject().to_string());
    assert_eq!(ini["signature.1.signer"]["serial"], serial.trim_start_matches('0'));
    assert_eq!(ini["signature.1.reference.1"]["name"], reference);
    let digest = recipes::hash(oids::DSTU7564_256, DOCUMENT.as_bytes(), None);
    assert_eq!(ini["signature.1.reference.1"]["digest"], to_hex_upper(&digest));
    assert_eq!(ini["signature.1.timestamp.1"]["kind"], "signature time-stamp");
    assert_eq!(ini["signature.1.timestamp.1"]["time"], signature["timestamp_time"]);
    assert!(ini["signature.1.timestamp.1"]["authority"].starts_with("CN=Test TSP Server,"));

    // The signer's path up to the root, and a "good" embedded response for the signer and for the issuing CA.
    let paths = sections_starting_with(&ini, "signature.1.path.");
    let signer_paths: Vec<_> = paths.iter().filter(|path| path["for"] == "signer").collect();
    assert_eq!(signer_paths.len(), 1);
    assert_eq!(
        signer_paths[0]["certificate.3"],
        pki.root.certificate.subject().to_string()
    );
    let ocsp = sections_starting_with(&ini, "signature.1.ocsp.");
    let good_embedded = ocsp
        .iter()
        .filter(|o| o["path"] == "signer" && o["status"] == "good" && o["source"] == "embedded")
        .count();
    assert_eq!(good_embedded, 2);
    let checks = &ini["signature.1.checks"];
    assert!(!checks.values().any(|check| check.starts_with("FAIL | ")));
    let warnings = checks.values().filter(|check| check.starts_with("WARN | ")).count();
    assert_eq!(signature["warnings"], warnings.to_string());

    // --report writes the same report (except the time of verification) in UTF-8 without a BOM.
    let file = std::fs::read(&report).unwrap();
    assert_ne!(file[0], 0xEF);
    let without_time = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| !line.starts_with("verified_at="))
            .map(str::to_owned)
            .collect()
    };
    assert_eq!(without_time(&output), without_time(&String::from_utf8(file).unwrap()));
}

#[test]
fn the_ini_report_of_a_cades_x_long_holds_every_detail() {
    ini_report_holds_every_detail("cades", "CAdES-X Long", "content");
}

#[test]
fn the_ini_report_of_an_asic_e_holds_every_detail() {
    ini_report_holds_every_detail("asic-e", "XAdES-B-LT", "doc.txt");
}

#[test]
fn the_report_format_is_checked() {
    let directory = TestDirectory::new("ua-sign-tests");
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let (code, output) = run(&["verify", "--in", &document, "--format", "json"]);
    assert_eq!(code, EXIT_ERROR, "{output}");
    assert!(output.contains("--format must be text or ini"), "{output}");
}

#[test]
fn online_verification_without_a_responder_keeps_the_warning() {
    let pki = Hierarchy::shared();
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = directory.path("signer.jks");
    pki.write_signer_key_store(&keystore, PASSWORD);
    let document = directory.write("doc.txt", DOCUMENT.as_bytes());
    let (code, output) = run(&[
        "sign",
        "--keystore",
        &keystore,
        "--password",
        PASSWORD,
        "--format",
        "cades",
        "--in",
        &document,
    ]);
    assert_eq!(code, EXIT_VALID, "{output}");

    // Level B carries only the signer's certificate: without the CA the output says how to get it.
    let signature = format!("{document}.p7s");
    let (code, output) = run(&["verify", "--in", &signature]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(output.contains("Hint: certificates are missing"), "{output}");

    // The synthetic certificates name no responder, so --online has nobody to ask: the warning stays.
    let ca = directory.write("ca.cer", pki.issuing_ca.certificate.encoded());
    let (code, output) = run(&["verify", "--in", &signature, "--online", "--certs", &ca]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(
        output.contains("[WARN] signer: revocation of 'Test Signer'"),
        "{output}"
    );
    assert!(!output.contains("Hint:"), "{output}");
}

#[test]
fn info_lists_the_key_store() {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "info.jks", &["--curve", "431", "--alias", "my key"]);
    let (code, output) = run(&["info", "--keystore", &keystore, "--password", PASSWORD]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(output.contains("[my key] private key"), "{output}");
    assert!(output.contains("PB m = 431"), "{output}");

    let certificate = testdata_path("certificates/intermediates/dia-knedp.cer");
    let (code, output) = run(&["info", "--cert", certificate.to_str().unwrap()]);
    assert_eq!(code, EXIT_VALID, "{output}");
    assert!(output.contains("OCSP http"), "{output}");
}

#[test]
fn passwords_come_from_the_environment_and_files() {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "key.jks", &[]);
    let password_file = directory.write("password.txt", format!("{PASSWORD}\n").as_bytes());
    let (code, output) = run(&["info", "--keystore", &keystore, "--password-file", &password_file]);
    assert_eq!(code, EXIT_VALID, "{output}");

    let variable = format!("UA_SIGN_TEST_PASSWORD_{}", std::process::id());
    let environment = |name: &str| (name == variable).then(|| PASSWORD.to_owned());
    let (code, output) = run_with_environment(
        &["info", "--keystore", &keystore, "--password-env", &variable],
        &environment,
    );
    assert_eq!(code, EXIT_VALID, "{output}");
    let (code, output) = run(&["info", "--keystore", &keystore, "--password-env", &variable]);
    assert_eq!(code, EXIT_ERROR, "{output}");
    assert!(output.contains("is not set"), "{output}");

    let (code, output) = run(&["info", "--keystore", &keystore, "--password", "wrong"]);
    assert_eq!(code, EXIT_ERROR, "{output}");
    assert!(output.contains("wrong password"), "{output}");
}

#[test]
fn usage_errors_exit_with_two() {
    let rows: [&[&str]; 7] = [
        &["frobnicate"],
        &["sign", "--format", "pdf", "--in", "x"],
        &["sign", "--format", "cades"],
        &["sign", "--format", "xades", "--in", "a", "--detached"],
        &["verify", "--unknown"],
        &["verify", "--in"],
        &[
            "keygen",
            "--keystore",
            "k.jks",
            "--subject",
            "CN=x",
            "--curve",
            "256",
            "--password",
            "p",
        ],
    ];
    for args in rows {
        let (code, output) = run(args);
        assert_eq!(code, EXIT_ERROR, "{args:?}: {output}");
    }
}

#[test]
fn existing_files_are_not_overwritten_without_force() {
    let directory = TestDirectory::new("ua-sign-tests");
    let keystore = keygen(&directory, "key.jks", &[]);
    let keygen_again = [
        "keygen",
        "--keystore",
        &keystore,
        "--subject",
        "CN=x",
        "--password",
        PASSWORD,
    ];
    assert_eq!(run(&keygen_again).0, EXIT_ERROR);
    let mut forced = keygen_again.to_vec();
    forced.push("--force");
    assert_eq!(run(&forced).0, EXIT_VALID);
    assert_eq!(run(&["--help"]).0, EXIT_VALID);
    assert_eq!(run(&["sign", "--help"]).0, EXIT_VALID);
}
