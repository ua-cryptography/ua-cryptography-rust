//! The X.509 layer on the public certificates of Ukrainian CAs and on the synthetic hierarchy: parsed fields equal
//! BouncyCastle's (recorded in `certificates/real.json`), keys equal those the recipe reads, signatures verify, and
//! certificates the crate issues are accepted by the independent recipes.

mod common;

use common::{
    Hierarchy, hex, oracle_certificate, read_json, real_certificate, real_certificate_files, recipes, to_hex,
};
use num_bigint::BigUint;
use ua_der::Asn1Node;
use ua_gf2m::FieldBasis;
use ua_pki::{
    Certificate, CertificateBuilder, DistinguishedName, Dstu4145PrivateKey, Dstu4145PublicKey, KeyError, KeyUsageFlags,
    oids,
};

fn all_real_certificate_files() -> Vec<String> {
    ["czo-roots", "intermediates", "historical", "nbu-roots"]
        .iter()
        .flat_map(|folder| real_certificate_files(folder))
        .collect()
}

#[test]
fn real_certificates_parse_like_bouncy_castle() {
    let real = read_json("certificates/real.json");
    let files = all_real_certificate_files();
    assert_eq!(files.len(), real["certificates"].as_object().unwrap().len());
    for file in files {
        let expected = &real["certificates"][&file];
        let certificate = real_certificate(&file);
        assert_eq!(
            i64::from(certificate.version()),
            expected["version"].as_i64().unwrap(),
            "{file}"
        );
        assert_eq!(
            certificate.serial_number().to_string(),
            expected["serialNumber"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            to_hex(certificate.subject().encoded()),
            expected["subject"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            to_hex(certificate.issuer().encoded()),
            expected["issuer"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            rfc3339(certificate.not_before()),
            expected["notBefore"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            rfc3339(certificate.not_after()),
            expected["notAfter"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            certificate.signature_algorithm(),
            expected["signatureAlgorithm"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            to_hex(certificate.tbs_encoded()),
            expected["tbsCertificate"].as_str().unwrap(),
            "{file}"
        );
        assert_eq!(
            to_hex(certificate.signature_value()),
            expected["signature"].as_str().unwrap(),
            "{file}"
        );
        let spki = expected["subjectPublicKeyInfo"].as_str().unwrap();
        assert_eq!(to_hex(certificate.subject_public_key_info()), spki, "{file}");
        let extension_count = expected["extensionCount"].as_u64().unwrap() as usize;
        assert_eq!(certificate.extensions().len(), extension_count, "{file}");
        assert_eq!(certificate.is_ca(), expected["isCa"].as_bool().unwrap(), "{file}");

        let key = certificate.public_key().unwrap();
        let expected_key = &expected["key"];
        assert_eq!(
            u64::from(key.domain().field().m()),
            expected_key["m"].as_u64().unwrap(),
            "{file}"
        );
        assert_eq!(
            key.domain().n(),
            &BigUint::from_bytes_be(&hex(expected_key["n"].as_str().unwrap())),
            "{file}"
        );
        let (qx, qy) = (key.q().x().unwrap().to_biguint(), key.q().y().unwrap().to_biguint());
        assert_eq!(
            qx,
            BigUint::from_bytes_be(&hex(expected_key["qx"].as_str().unwrap())),
            "{file}"
        );
        assert_eq!(
            qy,
            BigUint::from_bytes_be(&hex(expected_key["qy"].as_str().unwrap())),
            "{file}"
        );
        assert_eq!(key.dke().map(to_hex).as_deref(), expected_key["dke"].as_str(), "{file}");
    }
}

#[test]
fn real_certificate_signatures_verify_and_a_changed_byte_breaks_them() {
    let pairs = [
        (
            "czo-roots/czo-root-2027-gost34311.cer",
            "czo-roots/czo-root-2027-gost34311.cer",
        ),
        (
            "czo-roots/czo-root-2036-dstu7564.cer",
            "czo-roots/czo-root-2036-dstu7564.cer",
        ),
        ("historical/bitis-corp-2009.crt", "historical/bitis-root-2009.crt"),
        ("historical/ucc-ca-2010.crt", "historical/czo-root-2005.crt"),
        ("historical/ucc-tsp-2010.crt", "historical/ucc-ca-2010.crt"),
    ];
    for (subject, issuer) in pairs {
        let certificate = real_certificate(subject);
        let issuer = real_certificate(issuer);
        assert!(certificate.is_signed_by(&issuer), "{subject}");

        let mut tampered = certificate.encoded().to_vec();
        let name = certificate.subject().encoded();
        let offset = tampered.windows(name.len()).position(|window| window == name).unwrap() + name.len() - 1;
        tampered[offset] ^= 1;
        assert!(
            !Certificate::load(&tampered).unwrap().is_signed_by(&issuer),
            "{subject}"
        );
    }
}

#[test]
fn diia_ca_is_issued_by_exactly_one_czo_root() {
    let diia = real_certificate("intermediates/dia-knedp.cer");
    let roots = common::czo_roots();
    assert_eq!(roots.iter().filter(|root| diia.is_signed_by(root)).count(), 1);
    let urls = [diia.ocsp_urls(), diia.ca_issuer_urls(), diia.time_stamp_urls()].concat();
    assert!(!urls.is_empty());
}

#[test]
fn synthetic_hierarchy_verifies_with_the_crate() {
    let pki = Hierarchy::shared();
    let root = &pki.root.certificate;
    let ca = &pki.issuing_ca.certificate;
    assert!(root.is_signed_by(root));
    assert!(ca.is_signed_by(root));
    assert!(pki.signer.certificate.is_signed_by(ca));
    assert!(!pki.signer.certificate.is_signed_by(root));
    let purposes = pki.tsa.certificate.extended_key_usage();
    assert!(
        purposes
            .iter()
            .any(|purpose| purpose == oids::KEY_PURPOSE_TIME_STAMPING)
    );
}

#[test]
fn issued_certificates_are_accepted_by_the_recipes_and_read_back() {
    for (signature_algorithm, m) in [
        (oids::DSTU4145_WITH_DSTU7564, 257),
        (oids::DSTU4145_WITH_GOST34311, 431),
        (oids::DSTU4145_WITH_DSTU7564, 163),
    ] {
        let root_key = Dstu4145PrivateKey::generate(&ua_dstu4145::get_polynomial_curve(m).unwrap());
        let root_name = DistinguishedName::parse("CN=Package Root,O=UA Cryptography Tests,C=UA").unwrap();
        let mut root_builder = CertificateBuilder::new(root_name, root_key.public_key().clone()).unwrap();
        root_builder.signature_algorithm = signature_algorithm.to_owned();
        let root = root_builder
            .add_basic_constraints(true)
            .add_key_usage(KeyUsageFlags::KEY_CERT_SIGN | KeyUsageFlags::CRL_SIGN)
            .add_subject_key_identifier()
            .self_sign(&root_key)
            .unwrap();

        let leaf_key = Dstu4145PrivateKey::generate(&ua_dstu4145::get_polynomial_curve(257).unwrap());
        let leaf_name = DistinguishedName::parse("CN=Package Leaf,O=UA Cryptography Tests,C=UA").unwrap();
        let mut leaf_builder = CertificateBuilder::new(leaf_name, leaf_key.public_key().clone()).unwrap();
        leaf_builder.signature_algorithm = signature_algorithm.to_owned();
        let leaf = leaf_builder
            .add_basic_constraints(false)
            .add_key_usage(KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::NON_REPUDIATION)
            .add_authority_key_identifier(&root.subject_key_identifier().unwrap())
            .add_authority_info_access(Some("http://ocsp.example/"), Some("http://ca.example/ca.cer"))
            .add_time_stamping_url("http://tsp.example/")
            .issue(&root, &root_key)
            .unwrap();

        // The independent recipe reads and verifies them.
        assert!(recipes::verify_certificate(root.encoded(), root.encoded()));
        assert!(recipes::verify_certificate(leaf.encoded(), root.encoded()));
        assert_eq!(leaf.signature_algorithm(), signature_algorithm);
        assert_eq!(&recipes::read_public_key(leaf.encoded()).q, leaf_key.public_key().q());

        // The crate reads its own extensions back.
        assert!(root.is_ca() && !leaf.is_ca());
        assert_eq!(leaf.ocsp_urls(), ["http://ocsp.example/"]);
        assert_eq!(leaf.ca_issuer_urls(), ["http://ca.example/ca.cer"]);
        assert_eq!(leaf.time_stamp_urls(), ["http://tsp.example/"]);
        assert_eq!(leaf.authority_key_identifier(), root.subject_key_identifier());
        assert_eq!(leaf.key_usage(), Some(0b11));
        assert!(leaf.is_signed_by(&root));
        assert!(!root.is_signed_by(&leaf));
    }
}

#[test]
fn certificates_the_csharp_builder_issued_read_as_bouncy_castle_reads_them() {
    for case in read_json("certificates/package-issued.json").as_array().unwrap() {
        let root = oracle_certificate(case["root"]["file"].as_str().unwrap());
        for role in ["root", "leaf"] {
            let expected = &case[role];
            let certificate = oracle_certificate(expected["file"].as_str().unwrap());
            assert_eq!(
                certificate.signature_algorithm(),
                expected["sigAlgOid"].as_str().unwrap()
            );
            assert_eq!(certificate.is_ca(), expected["basicConstraints"].as_i64().unwrap() >= 0);
            let usage = certificate.key_usage().unwrap();
            for (bit, is_set) in expected["keyUsage"].as_array().unwrap().iter().enumerate() {
                assert_eq!(usage & (1 << bit) != 0, is_set.as_bool().unwrap(), "{role} bit {bit}");
            }
            let mut extensions: Vec<&str> = certificate.extensions().iter().map(|e| e.oid.as_str()).collect();
            extensions.sort();
            let expected_extensions: Vec<&str> = expected["extensionOids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|oid| oid.as_str().unwrap())
                .collect();
            assert_eq!(extensions, expected_extensions);
            let q = certificate.public_key().unwrap().q();
            let qx = BigUint::from_bytes_be(&hex(expected["qx"].as_str().unwrap()));
            assert_eq!(q.x().unwrap().to_biguint(), qx);
            let self_signed = expected["selfSignatureVerifies"].as_bool().unwrap();
            assert_eq!(certificate.is_signed_by(&certificate), self_signed);
            assert!(certificate.is_signed_by(&root));
            assert!(recipes::verify_certificate(certificate.encoded(), root.encoded()));
        }
    }
}

#[test]
fn a_normal_basis_key_round_trips_through_explicit_parameters() {
    // The national PKI does not use ONB and BouncyCastle has none: the explicit ECBinary form without a polynomial.
    let key = Dstu4145PrivateKey::generate(&ua_dstu4145::get_optimal_normal_curve(173).unwrap());
    let spki = key.public_key().to_subject_public_key_info().unwrap();
    let parsed = Dstu4145PublicKey::from_subject_public_key_info(&spki).unwrap();
    assert!(matches!(parsed.domain().field().basis(), FieldBasis::OptimalNormal(_)));
    assert_eq!(
        parsed.q().x().unwrap().to_biguint(),
        key.public_key().q().x().unwrap().to_biguint()
    );

    let signature = key.sign_hash(&[0u8; 32]).unwrap();
    assert!(parsed.verify_hash(&[0u8; 32], &signature));
    assert_eq!(
        Dstu4145PrivateKey::from_pkcs8(&key.to_pkcs8().unwrap()).unwrap().d(),
        key.d()
    );
}

#[test]
fn explicit_field_degrees_outside_the_standard_tables_are_refused() {
    // An attacker-chosen huge field would make the checks of section 8 arbitrarily expensive.
    for m in [131i64, 600, 100_000] {
        let ec_binary = ua_der::sequence([
            ua_der::sequence([ua_der::integer_from_i64(m), ua_der::integer_from_i64(3)]),
            ua_der::integer_from_i64(0),
            ua_der::octet_string(&[0u8; 8]),
            ua_der::integer_from_i64(12345),
            ua_der::octet_string(&[0u8; 8]),
        ]);
        let spki = ua_der::sequence([
            ua_der::sequence([
                ua_der::object_identifier(oids::DSTU4145_LE),
                ua_der::sequence([ec_binary]),
            ]),
            ua_der::bit_string(&ua_der::octet_string(&[0u8; 8])),
        ]);
        let refusal = Dstu4145PublicKey::from_subject_public_key_info(&spki).unwrap_err();
        assert_eq!(refusal, KeyError::UnsupportedFieldDegree { m });
    }
}

#[test]
fn the_big_endian_key_oid_reverses_the_octet_strings() {
    let little = Dstu4145PrivateKey::generate(&ua_dstu4145::get_polynomial_curve(257).unwrap());
    let dke = little.dke().map(<[u8]>::to_vec);
    let big = Dstu4145PrivateKey::new(little.domain().clone(), little.d().clone(), dke, false).unwrap();
    let little_spki = little.public_key().to_subject_public_key_info().unwrap();
    let big_spki = big.public_key().to_subject_public_key_info().unwrap();
    let key_bits = |spki: &[u8]| {
        let node = Asn1Node::parse(spki).unwrap();
        Asn1Node::parse(node.child(1).unwrap().to_bit_string().unwrap())
            .unwrap()
            .to_octet_string()
            .unwrap()
    };
    let big_oid = Asn1Node::parse(&big_spki)
        .unwrap()
        .child(0)
        .unwrap()
        .child(0)
        .unwrap()
        .to_oid()
        .unwrap();
    assert_eq!(big_oid, oids::DSTU4145_BE);
    let mut q = key_bits(&little_spki);
    q.reverse();
    assert_eq!(q, key_bits(&big_spki));
    assert_eq!(
        Dstu4145PublicKey::from_subject_public_key_info(&big_spki).unwrap().q(),
        little.public_key().q()
    );
    assert_eq!(
        Dstu4145PrivateKey::from_pkcs8(&big.to_pkcs8().unwrap()).unwrap().d(),
        little.d()
    );
}

#[test]
fn distinguished_names_encode_like_bouncy_castle() {
    let names = read_json("certificates/distinguished-names.json");
    let names = names["names"].as_array().unwrap();
    let ascii = DistinguishedName::parse(names[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(to_hex(ascii.encoded()), names[0]["der"].as_str().unwrap());

    let cyrillic = DistinguishedName::parse(names[1]["parsedFrom"].as_str().unwrap()).unwrap();
    assert_eq!(cyrillic.find_attribute(oids::COMMON_NAME), Some("Тестовий підписувач"));
    assert_eq!(cyrillic.find_attribute(oids::ORGANIZATION), Some("Організація, ТОВ"));
    let reread = DistinguishedName::from_asn1(&Asn1Node::parse(cyrillic.encoded()).unwrap()).unwrap();
    assert_eq!(reread, cyrillic);
    // BouncyCastle's DER of the crate's text form equals the crate's DER.
    assert_eq!(to_hex(cyrillic.encoded()), names[1]["der"].as_str().unwrap());
    assert_eq!(cyrillic.to_string(), names[1]["text"].as_str().unwrap());
    assert!(DistinguishedName::parse("XX=1").is_err());
}

#[test]
fn pem_and_der_load_the_same_certificate() {
    let der = real_certificate("intermediates/dia-knedp.cer");
    let pem = Certificate::load(ua_der::encode_pem(der.encoded(), "CERTIFICATE").as_bytes()).unwrap();
    assert_eq!(der, pem);
}

// ---- Historical certificates (2005 – 2015), checked with ua-dstu4145 and GOST 34.311 directly ----

#[test]
fn historical_certificate_signatures_verify_with_the_issuers_dke() {
    let cases = [
        ("bitis-root-2009.crt", "bitis-root-2009.crt", 257), // self-signed root, named curve
        ("bitis-corp-2009.crt", "bitis-root-2009.crt", 257),
        ("czo-root-2005.crt", "czo-root-2005.crt", 431), // the Central CA of 2005, explicit curve
        ("ucc-ca-2010.crt", "czo-root-2005.crt", 431),
        ("ucc-tsp-2010.crt", "ucc-ca-2010.crt", 257),
    ];
    for (subject, issuer, m) in cases {
        let certificate = real_certificate(&format!("historical/{subject}"));
        let issuer = real_certificate(&format!("historical/{issuer}"));
        assert_eq!(certificate.signature_algorithm(), oids::DSTU4145_WITH_GOST34311);
        let key = recipes::read_public_key(issuer.encoded());
        assert_eq!(key.domain.field().m(), m);

        // The signature value is an OCTET STRING with D (5.10) in little-endian byte order.
        let signature = recipes::reversed(&recipes::unwrap_signature(certificate.signature_value()));
        let signer = ua_dstu4145::Signer::new(&key.domain);
        let mut hasher = ua_gost::Gost34311::from_dke(key.dke.as_deref().unwrap()).unwrap();
        let tbs = certificate.tbs_encoded();
        assert!(
            signer.verify_message_with_hasher(&key.q, tbs, &signature, &mut hasher),
            "{subject}"
        );

        let mut changed = tbs.to_vec();
        changed[tbs.len() / 2] ^= 1;
        assert!(
            !signer.verify_message_with_hasher(&key.q, &changed, &signature, &mut hasher),
            "{subject}"
        );
    }
}

// ---- The trust anchors: the ЦЗО roots and the NBU root ----

#[test]
fn trust_anchors_are_present() {
    assert!(!real_certificate_files("czo-roots").is_empty());
    assert!(!real_certificate_files("nbu-roots").is_empty());
}

#[test]
fn every_root_is_self_signed_polynomial_431_and_verifies() {
    let roots = [real_certificate_files("czo-roots"), real_certificate_files("nbu-roots")].concat();
    for file in roots {
        let root = real_certificate(&file);
        assert!(root.is_self_issued(), "{file}");
        let key = recipes::read_public_key(root.encoded());
        assert!(
            matches!(key.domain.field().basis(), FieldBasis::Polynomial(_)),
            "{file}"
        );
        assert_eq!(key.domain.field().m(), 431, "{file}");
        assert!(recipes::verify_certificate(root.encoded(), root.encoded()), "{file}");
        assert!(root.is_signed_by(&root), "{file}");

        let mut tbs = root.tbs_encoded().to_vec();
        let middle = tbs.len() / 2;
        tbs[middle] ^= 1;
        let hash = recipes::hash(recipes::hash_of(root.signature_algorithm()), &tbs, key.dke.as_deref());
        let signature = recipes::unwrap_signature(root.signature_value());
        assert!(!recipes::verify_dstu4145(&key, &hash, &signature), "{file}");
    }
}

// ---- Chains that must (or must not) end at a trusted root ----

fn encodings(certificates: &[Certificate]) -> Vec<Vec<u8>> {
    certificates
        .iter()
        .map(|certificate| certificate.encoded().to_vec())
        .collect()
}

#[test]
fn the_diia_issuing_ca_chains_to_a_trusted_czo_root() {
    let diia = real_certificate("intermediates/dia-knedp.cer");
    let trusted = encodings(&common::czo_roots());
    assert!(recipes::chains_to_trusted(diia.encoded(), &trusted, &trusted));
}

#[test]
fn the_privatbank_issuing_ca_chains_to_the_nbu_root_and_not_to_czo() {
    let privatbank = real_certificate("intermediates/privatbank-knedp.cer");
    let nbu: Vec<Vec<u8>> = real_certificate_files("nbu-roots")
        .iter()
        .map(|file| real_certificate(file).encoded().to_vec())
        .collect();
    assert!(recipes::chains_to_trusted(privatbank.encoded(), &nbu, &nbu));
    let czo = encodings(&common::czo_roots());
    assert!(!recipes::chains_to_trusted(privatbank.encoded(), &czo, &czo));
}

#[test]
fn the_synthetic_chain_is_refused_by_czo_trust() {
    let pki = Hierarchy::shared();
    let chain = encodings(&pki.signer_chain());
    let root = vec![pki.root.certificate.encoded().to_vec()];
    assert!(recipes::chains_to_trusted(
        pki.signer.certificate.encoded(),
        &chain,
        &root
    ));
    let czo = encodings(&common::czo_roots());
    assert!(!recipes::chains_to_trusted(
        pki.signer.certificate.encoded(),
        &chain,
        &czo
    ));
}

#[test]
fn a_chain_with_a_foreign_issuer_of_the_same_name_is_refused() {
    // Same issuer name, different key: the link does not verify.
    let pki = Hierarchy::shared();
    let impostor_key = Dstu4145PrivateKey::generate(&ua_dstu4145::get_polynomial_curve(257).unwrap());
    let impostor = CertificateBuilder::new(
        pki.root.certificate.subject().clone(),
        impostor_key.public_key().clone(),
    )
    .unwrap()
    .add_basic_constraints(true)
    .self_sign(&impostor_key)
    .unwrap();
    let impostor = vec![impostor.encoded().to_vec()];
    assert!(!recipes::chains_to_trusted(
        pki.issuing_ca.certificate.encoded(),
        &impostor,
        &impostor
    ));
    assert!(
        !pki.issuing_ca
            .certificate
            .is_signed_by(&Certificate::load(&impostor[0]).unwrap())
    );
}

fn rfc3339(time: time::OffsetDateTime) -> String {
    time.format(&time::format_description::well_known::Rfc3339).unwrap()
}
