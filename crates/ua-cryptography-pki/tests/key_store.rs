//! The JKS reader and writer against the stores of the two C# writers (the independent test implementation
//! `Support/Jks.cs` and the C# package) and an independent check of the Rust writer's output; several entries, Java's
//! modified UTF-8 and every way a password can be wrong.

mod common;

use common::{Hierarchy, PASSWORD, hex, oracle_certificate, read_json, read_oracle};
use num_bigint::BigUint;
use sha1::{Digest, Sha1};
use ua_cryptography_der::Asn1Node;
use ua_cryptography_pki::{
    CertificateBuilder, DistinguishedName, Dstu4145PrivateKey, JksEntry, JksKeyStore, KeyStoreError, KeyUsageFlags,
    SigningKey,
};

fn password_bytes(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// An independent reading of the Sun key protector: the PKCS#8 bytes of a protected key.
fn unprotect(protected: &[u8], password: &str) -> Vec<u8> {
    let info = Asn1Node::parse(protected).unwrap();
    let encrypted = info.child(1).unwrap().to_octet_string().unwrap();
    let (salt, rest) = encrypted.split_at(20);
    let (masked, check) = rest.split_at(rest.len() - 20);
    let password = password_bytes(password);
    let mut stream = Vec::new();
    let mut previous = salt.to_vec();
    while stream.len() < masked.len() {
        previous = Sha1::new()
            .chain_update(&password)
            .chain_update(&previous)
            .finalize()
            .to_vec();
        stream.extend_from_slice(&previous);
    }
    let key: Vec<u8> = masked.iter().zip(&stream).map(|(byte, mask)| byte ^ mask).collect();
    assert_eq!(
        Sha1::new()
            .chain_update(&password)
            .chain_update(&key)
            .finalize()
            .as_slice(),
        check
    );
    key
}

#[test]
fn a_store_the_crate_writes_passes_an_independent_check_and_reads_back() {
    let pki = Hierarchy::shared();
    let mut store = JksKeyStore::new();
    store
        .add_private_key("signer", &pki.signer.key, pki.signer_chain(), PASSWORD)
        .unwrap();
    let saved = store.save(PASSWORD).unwrap();

    // Integrity: SHA-1(password UTF-16BE ‖ "Mighty Aphrodite" ‖ body).
    let (body, integrity) = saved.split_at(saved.len() - 20);
    let expected = Sha1::new()
        .chain_update(password_bytes(PASSWORD))
        .chain_update(b"Mighty Aphrodite")
        .chain_update(body)
        .finalize();
    assert_eq!(expected.as_slice(), integrity);
    assert_eq!(&body[..4], &[0xFE, 0xED, 0xFE, 0xED]);

    let read = JksKeyStore::load(&saved, PASSWORD).unwrap();
    let entry = read.private_keys().next().unwrap();
    assert_eq!(entry.alias, "signer");
    assert_eq!(entry.chain, pki.signer_chain());
    let pkcs8 = unprotect(&entry.protected_key, PASSWORD);
    assert_eq!(Dstu4145PrivateKey::from_pkcs8(&pkcs8).unwrap().d(), pki.signer.key.d());
    assert_eq!(entry.get_private_key(PASSWORD).unwrap().d(), pki.signer.key.d());
}

#[test]
fn stores_of_both_csharp_writers_are_read() {
    let pki = Hierarchy::shared();
    for file in ["jks/test-impl-signer.jks", "jks/package-signer.jks"] {
        let store = JksKeyStore::load(&read_oracle(file), PASSWORD).unwrap();
        assert_eq!(store.entries().len(), 1, "{file}");
        let JksEntry::PrivateKey(entry) = &store.entries()[0] else {
            panic!("{file}: not a private key");
        };
        let key = entry.get_private_key(PASSWORD).unwrap();
        assert_eq!(key.d(), pki.signer.key.d(), "{file}");
        assert_eq!(key.public_key().q(), pki.signer.key.public_key().q(), "{file}");
        assert_eq!(key.dke(), pki.signer.key.dke(), "{file}");
        assert_eq!(entry.chain, pki.signer_chain(), "{file}");
        assert!(entry.chain[0].is_signed_by(&entry.chain[1]));

        let signer = SigningKey::from_jks(&store, PASSWORD, None, None).unwrap();
        assert_eq!(signer.certificate(), &pki.signer.certificate, "{file}");
    }
}

#[test]
fn a_chain_stored_root_first_with_a_key_agreement_certificate_is_reordered() {
    // As PrivatBank issues keys: root, CA, the signing certificate, then the certificate of the key-agreement key.
    let pki = Hierarchy::shared();
    let agreement_key = Dstu4145PrivateKey::generate(&ua_cryptography_dstu4145::get_polynomial_curve(431).unwrap());
    let agreement = CertificateBuilder::new(
        pki.signer.certificate.subject().clone(),
        agreement_key.public_key().clone(),
    )
    .unwrap()
    .add_key_usage(KeyUsageFlags::KEY_AGREEMENT)
    .issue(&pki.issuing_ca.certificate, &pki.issuing_ca.key)
    .unwrap();
    let stored_chain = vec![
        pki.root.certificate.clone(),
        pki.issuing_ca.certificate.clone(),
        pki.signer.certificate.clone(),
        agreement,
    ];
    let mut store = JksKeyStore::new();
    store
        .add_private_key("pb_sign", &pki.signer.key, stored_chain, PASSWORD)
        .unwrap();
    let rust_written = store.save(PASSWORD).unwrap();

    for data in [rust_written, read_oracle("jks/test-impl-root-first-agreement.jks")] {
        let read = JksKeyStore::load(&data, PASSWORD).unwrap();
        let entry = read.private_keys().next().unwrap();
        let key = entry.get_private_key(PASSWORD).unwrap();
        assert_eq!(entry.find_certificate(key.public_key()), Some(&pki.signer.certificate));
        let signer = SigningKey::from_jks(&read, PASSWORD, None, None).unwrap();
        assert_eq!(signer.certificate(), &pki.signer.certificate);
        assert_eq!(signer.chain(), pki.signer_chain().as_slice());
    }

    // A key that matches none of the certificates is still refused.
    let mut other = JksKeyStore::new();
    other
        .add_private_key(
            "other",
            &agreement_key,
            pki.signer_chain().into_iter().rev().collect(),
            PASSWORD,
        )
        .unwrap();
    for data in [
        other.save(PASSWORD).unwrap(),
        read_oracle("jks/test-impl-key-matches-no-certificate.jks"),
    ] {
        let read = JksKeyStore::load(&data, PASSWORD).unwrap();
        let refusal = SigningKey::from_jks(&read, PASSWORD, None, None).unwrap_err();
        assert!(
            matches!(refusal, KeyStoreError::KeyCertificateMismatch { .. }),
            "{refusal}"
        );
    }
}

#[test]
fn several_entries_and_unusual_aliases_round_trip() {
    let pki = Hierarchy::shared();
    let aliases = ["підпис", "nul\u{0}char", "emoji \u{1F511}"];
    let mut store = JksKeyStore::new();
    for alias in aliases {
        let key = Dstu4145PrivateKey::generate(&ua_cryptography_dstu4145::get_polynomial_curve(257).unwrap());
        let name = DistinguishedName::parse(&format!("CN=Key {}", alias.encode_utf16().count())).unwrap();
        let certificate = CertificateBuilder::new(name, key.public_key().clone())
            .unwrap()
            .self_sign(&key)
            .unwrap();
        store.add_private_key(alias, &key, vec![certificate], PASSWORD).unwrap();
    }
    store
        .add_trusted_certificate("root", pki.root.certificate.clone())
        .unwrap();
    assert!(matches!(
        store.add_trusted_certificate("ROOT", pki.root.certificate.clone()),
        Err(KeyStoreError::DuplicateAlias { .. })
    ));
    let saved = store.save(PASSWORD).unwrap();

    for data in [saved.clone(), read_oracle("jks/package-several-entries.jks")] {
        let read = JksKeyStore::load(&data, PASSWORD).unwrap();
        let read_aliases: Vec<&str> = read.entries().iter().map(JksEntry::alias).collect();
        assert_eq!(read_aliases, [aliases[0], aliases[1], aliases[2], "root"]);
        let Some(JksEntry::TrustedCertificate(root)) = read.find("root") else {
            panic!("no trusted root");
        };
        assert_eq!(root.certificate.subject(), pki.root.certificate.subject());
        for entry in read.private_keys() {
            let key = entry.get_private_key(PASSWORD).unwrap();
            assert_eq!(entry.chain[0].public_key().unwrap().q(), key.public_key().q());
        }

        // Several keys: the alias decides, compared ignoring case.
        let refusal = SigningKey::from_jks(&read, PASSWORD, None, None).unwrap_err();
        assert!(matches!(refusal, KeyStoreError::SeveralKeys { .. }));
        let chosen = SigningKey::from_jks(&read, PASSWORD, Some("ПІДПИС"), None).unwrap();
        assert_eq!(chosen.certificate(), &read.private_keys().next().unwrap().chain[0]);
    }

    // Java writes U+0000 as C0 80 (modified UTF-8), never as a zero byte.
    assert!(!saved.windows(4).any(|window| window == b"nul\0"));
    assert!(saved.windows(5).any(|window| window == [b'n', b'u', b'l', 0xC0, 0x80]));
    // The fixture lists the aliases as UTF-16 code units.
    let stores = read_json("jks/jks.json");
    let several = stores["stores"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["file"] == "jks/package-several-entries.jks")
        .unwrap();
    let utf16 = several["entries"][2]["aliasUtf16"].as_str().unwrap();
    let units: Vec<u16> = hex(utf16)
        .chunks(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect();
    assert_eq!(String::from_utf16(&units).unwrap(), aliases[2]);
}

#[test]
fn wrong_passwords_and_damage_are_detected() {
    let pki = Hierarchy::shared();
    let mut store = JksKeyStore::new();
    store
        .add_private_key(
            "signer",
            &pki.signer.key,
            vec![pki.signer.certificate.clone()],
            "key password",
        )
        .unwrap();
    let rust_written = store.save(PASSWORD).unwrap();

    for data in [rust_written.clone(), read_oracle("jks/package-key-password.jks")] {
        assert_eq!(
            JksKeyStore::load(&data, "wrong").unwrap_err(),
            KeyStoreError::IntegrityCheckFailed
        );
        let read = JksKeyStore::load(&data, PASSWORD).unwrap();
        let entry = read.private_keys().next().unwrap();
        assert_eq!(
            entry.get_private_key(PASSWORD).unwrap_err(),
            KeyStoreError::WrongKeyPassword
        );
        assert_eq!(entry.get_private_key("key password").unwrap().d(), pki.signer.key.d());
        let signer = SigningKey::from_jks(&read, PASSWORD, None, Some("key password")).unwrap();
        assert_eq!(signer.certificate(), &pki.signer.certificate);
    }

    for offset in (0..rust_written.len()).step_by(97) {
        let mut damaged = rust_written.clone();
        damaged[offset] ^= 0x40;
        assert!(JksKeyStore::load(&damaged, PASSWORD).is_err(), "damage at {offset}");
    }
    assert_eq!(
        JksKeyStore::load(&[0u8; 10], PASSWORD).unwrap_err(),
        KeyStoreError::TooShort
    );
}

#[test]
fn a_key_that_does_not_match_its_certificate_is_refused() {
    let pki = Hierarchy::shared();
    let mut store = JksKeyStore::new();
    store
        .add_private_key(
            "mismatch",
            &pki.signer.key,
            vec![pki.issuing_ca.certificate.clone()],
            PASSWORD,
        )
        .unwrap();
    for data in [
        store.save(PASSWORD).unwrap(),
        read_oracle("jks/test-impl-key-certificate-mismatch.jks"),
    ] {
        let read = JksKeyStore::load(&data, PASSWORD).unwrap();
        let refusal = read
            .private_keys()
            .next()
            .unwrap()
            .get_private_key(PASSWORD)
            .unwrap_err();
        assert_eq!(
            refusal,
            KeyStoreError::KeyCertificateMismatch {
                alias: "mismatch".to_owned()
            }
        );
    }
}

#[test]
fn pkcs8_accepts_the_bouncy_castle_integer_form() {
    let fixture = read_json("jks/jks.json");
    let d = BigUint::from_bytes_be(&hex(fixture["pkcs8"]["d"].as_str().unwrap()));
    for file in ["jks/pkcs8-octet-string.der", "jks/pkcs8-integer.der"] {
        assert_eq!(
            Dstu4145PrivateKey::from_pkcs8(&read_oracle(file)).unwrap().d(),
            &d,
            "{file}"
        );
    }

    // The form written from a key of the crate.
    let key = Dstu4145PrivateKey::generate(&ua_cryptography_dstu4145::get_polynomial_curve(257).unwrap());
    let pkcs8 = key.to_pkcs8().unwrap();
    let node = Asn1Node::parse(&pkcs8).unwrap();
    let integer_form = ua_cryptography_der::sequence([
        node.child(0).unwrap().encoded().to_vec(),
        node.child(1).unwrap().encoded().to_vec(),
        ua_cryptography_der::octet_string(&ua_cryptography_der::integer_from_unsigned(key.d())),
    ]);
    assert_eq!(Dstu4145PrivateKey::from_pkcs8(&integer_form).unwrap().d(), key.d());
    assert_eq!(read_oracle("jks/pkcs8-octet-string.der").len(), pkcs8.len());
}

#[test]
fn the_stores_of_the_test_implementation_open_with_their_passwords_only() {
    let store = JksKeyStore::load(&read_oracle("jks/test-impl-password-right.jks"), "right").unwrap();
    let entry = store.private_keys().next().unwrap();
    assert_eq!(entry.chain, [oracle_certificate("jks/standalone.cer")]);
    assert!(entry.get_private_key("right").is_ok());
    assert_eq!(
        JksKeyStore::load(&read_oracle("jks/test-impl-password-right.jks"), "wrong").unwrap_err(),
        KeyStoreError::IntegrityCheckFailed
    );
}
