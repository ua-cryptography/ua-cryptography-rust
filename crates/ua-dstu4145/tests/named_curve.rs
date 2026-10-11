//! The recommended curves of Appendix Г, the checks of section 8, signing and verification, the encoding of D.

mod common;

use common::{get_recommended_curve, recommended_curves};
use num_bigint::BigUint;
use num_traits::One;
use rand_core::{OsRng, RngCore};
use ua_dstu4145::{
    DomainParameters, NamedCurveError, ParameterCheckFailure, PublicKeyCheckFailure, SignatureEncodingError, Signer,
    decode_signature, encode_signature, get_optimal_normal_curve, get_polynomial_curve, get_polynomial_curve_by_index,
};
use ua_gf2m::{BinaryCurve, CurvePoint, FieldElement, parse_hex};

#[test]
fn every_recommended_curve_passes_section_8() {
    for (basis, m) in recommended_curves() {
        assert_eq!(Ok(()), get_recommended_curve(basis, m).validate(), "{basis} {m}");
    }
}

#[test]
fn every_recommended_curve_signs_and_verifies() {
    for (basis, m) in recommended_curves() {
        let parameters = get_recommended_curve(basis, m);
        let mut signer = Signer::new(&parameters);
        let key = signer.generate_key_pair();
        assert_eq!(Ok(()), parameters.validate_public_key(&key.public_key), "{basis} {m}");

        let mut hash = [0u8; 32];
        OsRng.fill_bytes(&mut hash);
        let signature = signer.sign_hash(&key.private_key, &hash).unwrap();
        assert_eq!(
            parameters.minimum_signature_bits() as usize / 8,
            signature.len(),
            "{basis} {m}"
        );
        assert!(signer.verify_hash(&key.public_key, &hash, &signature), "{basis} {m}");

        // Longer encodings are accepted too (5.7: any L_D ≥ 2 L(n), a multiple of 16).
        let long_bits = parameters.minimum_signature_bits() + 64;
        let long_signature = signer
            .sign_hash_with_length(&key.private_key, &hash, long_bits)
            .unwrap();
        assert!(
            signer.verify_hash(&key.public_key, &hash, &long_signature),
            "{basis} {m}"
        );

        let mut bad_hash = hash;
        bad_hash[31] ^= 0x01; // the low bits of the hash always enter h (5.9)
        assert!(
            !signer.verify_hash(&key.public_key, &bad_hash, &signature),
            "{basis} {m}"
        );

        let other = signer.generate_key_pair();
        assert!(!signer.verify_hash(&other.public_key, &hash, &signature), "{basis} {m}");
    }
}

#[test]
fn the_published_onb_curves_are_frobenius_images_of_table_g2() {
    // Values of table 2.2 published by the 2010 cryptography.org.ua project that differ from table Г.2: the same
    // curves seen through a power of the Frobenius map.
    let published = [
        (
            179,
            94,
            "19C9EBC4FD8308193D3A61762C547C82F2E6B2182CBCB",
            "11F4112265410477159E0D3E39BC4AC4ADE43B21B66B9",
            "2CA5F0B34C61A86216F13766591CB266E2819EE582B3C",
        ),
        (
            191,
            190,
            "13871C9D29D6CEEA740FD57444F72FDBAE559C13A1E31EF8",
            "7159E0D3E39BC4AC4ADE43B21B66B94F2AF25ABEEB1D85D3",
            "57E45D546BE6201E9705E029535D009D31F51D81E18226BE",
        ),
        (
            431,
            234,
            "53FB7AF7B4407000A6F226AD6BAD28378646BD83F1F940810A4C19536EE65E53F40F973F2F06C5E80EFE3B43651BD5FF8B06BA5F9299",
            "2020182CFCD7C724157B363D4ABFD4C16251773C595D4E5C88572FA9D5EBB58142326448C08D3EE3E17E40B835D3090DCFBA7C5ADEA6",
            "18E1B6EFB28EEF8A1F9C1859ED57C74CA747E4E1A60294C005D1920E80903A432929855828DD7F21714F837E119A044987F00110ADAD",
        ),
    ];
    for (m, j, b, x, y) in published {
        let p = get_optimal_normal_curve(m).unwrap();
        let g = p.base_point();
        assert_eq!(
            parse_hex(b).unwrap(),
            p.curve().b().square_times(j).to_biguint(),
            "m = {m}"
        );
        assert_eq!(
            parse_hex(x).unwrap(),
            g.x().unwrap().square_times(j).to_biguint(),
            "m = {m}"
        );
        assert_eq!(
            parse_hex(y).unwrap(),
            g.y().unwrap().square_times(j).to_biguint(),
            "m = {m}"
        );

        // The published point is a valid base point of the published curve.
        let published_b = FieldElement::from_hex(p.field(), b).unwrap();
        let published_curve = BinaryCurve::new(p.field(), p.curve().a(), &published_b).unwrap();
        let published_g = CurvePoint::from_hex(&published_curve, x, y).unwrap();
        assert!(published_curve.multiply(&published_g, p.n()).is_infinity(), "m = {m}");
    }
}

#[test]
fn a_freshly_generated_base_point_is_valid() {
    // 7.3
    let p = get_optimal_normal_curve(173).unwrap();
    let g = DomainParameters::generate_base_point(p.curve(), p.n(), &mut OsRng);
    let generated = DomainParameters::new(p.curve(), &g, p.n()).unwrap();
    assert_eq!(Ok(()), generated.validate());
}

#[test]
fn validation_detects_broken_parameters() {
    let p = get_polynomial_curve(163).unwrap();
    let wrong_order = DomainParameters::new(p.curve(), p.base_point(), &(p.n() + 2u32)).unwrap();
    assert!(wrong_order.validate().is_err(), "not prime / not the order");
    let at_infinity = DomainParameters::new(p.curve(), &p.curve().infinity(), p.n()).unwrap();
    assert_eq!(Err(ParameterCheckFailure::BasePointAtInfinity), at_infinity.validate());
    assert_eq!(
        Err(PublicKeyCheckFailure::AtInfinity),
        p.validate_public_key(&p.curve().infinity())
    );

    // A random point has order 2n with probability 1/2; retry until one lies outside the subgroup.
    let mut random = p.curve().random_point(&mut OsRng);
    for _ in 0..64 {
        if !p.curve().multiply(&random, p.n()).is_infinity() {
            break;
        }
        random = p.curve().random_point(&mut OsRng);
    }
    assert_eq!(
        Err(PublicKeyCheckFailure::OrderMismatch),
        p.validate_public_key(&random)
    );
}

#[test]
fn the_mov_condition_holds_for_table_g1_and_fails_for_a_mersenne_order() {
    for m in ua_dstu4145::POLYNOMIAL_DEGREES {
        assert!(
            DomainParameters::check_mov_condition(get_polynomial_curve(m).unwrap().n(), m),
            "m = {m}"
        );
    }
    // 2^m = 1 mod n for n = 2^m − 1
    let mersenne = (BigUint::one() << 127u32) - 1u32;
    assert!(!DomainParameters::check_mov_condition(&mersenne, 127));
}

#[test]
fn the_signature_is_s_then_r_in_halves_of_l_d() {
    let (r, s) = (parse_hex("ABCDEF").unwrap(), parse_hex("123456").unwrap());
    let d = encode_signature(&r, &s, 64).unwrap();
    assert_eq!(vec![0x00, 0x12, 0x34, 0x56, 0x00, 0xAB, 0xCD, 0xEF], d);
    assert_eq!(Ok((r.clone(), s.clone())), decode_signature(&d));
    assert_eq!(
        Err(SignatureEncodingError::LengthNotMultipleOf16(60)),
        encode_signature(&r, &s, 60)
    );
    assert_eq!(
        Err(SignatureEncodingError::ValueOutOfRange),
        encode_signature(&(BigUint::one() << 40u32), &s, 64)
    );
}

#[test]
fn curves_outside_the_tables_are_not_found() {
    assert_eq!(
        Err(NamedCurveError::NotInTableG1(165)),
        get_polynomial_curve(165).map(|_| ())
    );
    assert_eq!(
        Err(NamedCurveError::NotInTableG2(163)),
        get_optimal_normal_curve(163).map(|_| ())
    );
    assert_eq!(
        Err(NamedCurveError::IndexOutOfRange(10)),
        get_polynomial_curve_by_index(10).map(|_| ())
    );
    assert_eq!(
        get_polynomial_curve(257).unwrap(),
        get_polynomial_curve_by_index(6).unwrap()
    );
}
