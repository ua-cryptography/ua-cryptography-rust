//! ASiC-S and ASiC-E made by the crate pass the structural checks of the tests and the crate's verifier, and are
//! written as the C# AsicContainer writes them; the containers of the C# test builders verify too; unsigned or
//! replaced entries and a wrong media type are caught.

mod common;

use common::{Hierarchy, TestOcsp, TestTimeStamps, describe, has_check, read_oracle, read_zip, write_zip, xml};
use ua_cryptography_pki::{
    CadesOptions, CadesSigner, CheckStatus, SignatureLevel, SignatureServices, SignedFile, ValidationOptions,
    VerificationResult, XadesSigner, asic_container, oids, signature_verifier,
};

fn files() -> [SignedFile; 2] {
    [
        SignedFile {
            name: "contract.pdf".to_owned(),
            content: b"%PDF-1.7 fake".to_vec(),
        },
        SignedFile {
            name: "annex/табл.csv".to_owned(),
            content: b"a;b\n1;2".to_vec(),
        },
    ]
}

fn verify(container: &[u8]) -> VerificationResult {
    signature_verifier::verify(container, &|_: Option<&str>| None, &Hierarchy::shared().trusting()).unwrap()
}

fn asic_e(level: SignatureLevel) -> Vec<u8> {
    let time_stamps = TestTimeStamps::new();
    let ocsp = TestOcsp::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ocsp: Some(&ocsp),
        ..SignatureServices::default()
    };
    let files = files();
    let signature = XadesSigner::new(Hierarchy::shared().signing_key(), services)
        .sign(&files, oids::DSTU7564_256, level)
        .unwrap();
    asic_container::create_asic_e(&files, &signature).unwrap()
}

#[test]
fn the_crate_asic_s_is_well_formed_and_verifies() {
    let files = files();
    let time_stamps = TestTimeStamps::new();
    let services = SignatureServices {
        time_stamps: Some(&time_stamps),
        ..SignatureServices::default()
    };
    let options = CadesOptions {
        hash_oid: oids::GOST34311.to_owned(),
        is_detached: true,
        level: SignatureLevel::T,
        ..CadesOptions::default()
    };
    let cades = CadesSigner::new(Hierarchy::shared().signing_key(), services)
        .sign(&files[0].content, &options)
        .unwrap();
    let container = asic_container::create_asic_s(&files[0].name, &files[0].content, &cades).unwrap();

    let entries = read_zip(&container);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        ["mimetype", "contract.pdf", asic_container::ASIC_S_SIGNATURE_ENTRY]
    );
    assert!(entries[0].is_stored);
    assert_eq!(entries[0].content, asic_container::ASIC_S_MIME_TYPE.as_bytes());

    let result = verify(&container);
    assert!(result.is_valid(), "{}", describe(&result));
    assert_eq!(result.format, "ASiC-S");
    assert_eq!(
        result.find_signed_file("contract.pdf"),
        Some(files[0].content.as_slice())
    );
}

#[test]
fn the_crate_asic_e_is_well_formed_verifies_and_matches_the_csharp_container() {
    let container = asic_e(SignatureLevel::LT);
    let entries = read_zip(&container);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "mimetype",
            "contract.pdf",
            "annex/табл.csv",
            "META-INF/manifest.xml",
            "META-INF/signatures001.xml"
        ]
    );
    assert!(entries[0].is_stored);

    let result = verify(&container);
    assert!(result.is_valid(), "{}", describe(&result));
    assert_eq!(result.format, "ASiC-E");
    assert_eq!(result.signed_files.len(), 2);
    assert!(has_check(&result.signatures[0], "manifest", CheckStatus::Passed));

    // The C# AsicContainer wrote the same files: the same manifest, the same signature document structure.
    for (file, level) in [
        ("package/asice-dstu7564-b.asice", SignatureLevel::B),
        ("package/asice-dstu7564-lt.asice", SignatureLevel::LT),
    ] {
        let csharp = read_zip(&read_oracle(file));
        let rust = read_zip(&asic_e(level));
        let csharp_names: Vec<&str> = csharp.iter().map(|entry| entry.name.as_str()).collect();
        let rust_names: Vec<&str> = rust.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(rust_names, csharp_names);
        assert_eq!(rust[3].content, csharp[3].content, "{file}: manifest");
        let skeleton = |content: &[u8]| xml::skeleton(std::str::from_utf8(content).unwrap());
        assert_eq!(
            skeleton(&rust[4].content),
            skeleton(&csharp[4].content),
            "{file}: signatures"
        );
    }
}

#[test]
fn the_test_builder_containers_verify() {
    for file in [
        "xades/asice-dstu7564-b.asice",
        "cades/asics-gost34311-t-content-ts.asics",
    ] {
        let result = verify(&read_oracle(file));
        assert!(result.is_valid(), "{file}: {}", describe(&result));
    }
}

#[test]
fn added_or_replaced_entries_are_caught() {
    let files = files();
    let signature = XadesSigner::new(Hierarchy::shared().signing_key(), SignatureServices::default())
        .sign(&files, oids::DSTU7564_256, SignatureLevel::B)
        .unwrap();
    let container = asic_container::create_asic_e(&files, &signature).unwrap();
    let entries = read_zip(&container);

    let mut added: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.content.as_slice()))
        .collect();
    added.push(("unsigned.txt", b"not signed"));
    let result = verify(&write_zip(&added));
    assert!(!result.is_valid());
    assert!(has_check(
        &result.signatures[0],
        "file 'unsigned.txt'",
        CheckStatus::Failed
    ));

    let mut replaced: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|e| e.name != "contract.pdf")
        .map(|e| (e.name.as_str(), e.content.as_slice()))
        .collect();
    replaced.push(("contract.pdf", b"%PDF-1.7 forged"));
    let result = verify(&write_zip(&replaced));
    assert!(!result.is_valid());
    assert!(has_check(
        &result.signatures[1],
        "reference 'contract.pdf'",
        CheckStatus::Failed
    ));
}

#[test]
fn a_wrong_media_type_is_reported() {
    let files = files();
    let signature = XadesSigner::new(Hierarchy::shared().signing_key(), SignatureServices::default())
        .sign(&files, oids::DSTU7564_256, SignatureLevel::B)
        .unwrap();
    let entries = read_zip(&asic_container::create_asic_e(&files, &signature).unwrap());
    // The mimetype entry deleted and written again: last, with another media type.
    let mut rewritten: Vec<(&str, &[u8])> = entries
        .iter()
        .filter(|e| e.name != "mimetype")
        .map(|e| (e.name.as_str(), e.content.as_slice()))
        .collect();
    rewritten.push(("mimetype", b"application/zip"));
    let result = signature_verifier::verify(
        &write_zip(&rewritten),
        &|_: Option<&str>| None,
        &ValidationOptions::default(),
    )
    .unwrap();
    assert!(!result.is_valid());
    assert_eq!(result.format, "ZIP");
    assert!(has_check(&result.signatures[0], "mimetype", CheckStatus::Failed));
}

#[test]
fn entry_names_that_escape_the_container_are_refused() {
    for name in ["mimetype", "../evil.txt", "/etc/passwd"] {
        let refusal = asic_container::create_asic_s(name, b"data", b"signature").unwrap_err();
        assert_eq!(
            refusal,
            ua_cryptography_pki::ContainerError::InvalidEntryName { name: name.to_owned() }
        );
    }
    assert!(asic_container::looks_like_zip(
        &asic_container::create_asic_s("a.txt", b"a", b"s").unwrap()
    ));
    assert!(!asic_container::looks_like_zip(b"<xml/>"));
}
