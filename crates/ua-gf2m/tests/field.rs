//! Fields over the public API: bases, the standard representation, the optimal normal basis against X9.62.

mod common;

use common::TestRandom;
use num_bigint::BigUint;
use ua_gf2m::{BinaryField, FieldElement, FieldError, OptimalNormalBasis};

fn element(field: &BinaryField, value: &BigUint) -> FieldElement {
    FieldElement::from_biguint(field, value).unwrap()
}

#[test]
fn a_reducible_trinomial_is_detected() {
    // t^163 + t^3 + 1 is not irreducible (the recommended pentanomial is used for m = 163).
    let field = BinaryField::polynomial(163, 3, 0, 0).unwrap();
    let ua_gf2m::FieldBasis::Polynomial(basis) = field.basis() else {
        panic!("a polynomial basis was built")
    };
    assert!(!basis.is_irreducible());
}

#[test]
fn the_degrees_of_table_2_have_a_type_two_basis_and_others_do_not() {
    for m in OptimalNormalBasis::STANDARD_DEGREES {
        assert!(OptimalNormalBasis::has_type_two_basis(m), "m = {m}");
    }
    assert!(!OptimalNormalBasis::has_type_two_basis(163));
    assert!(!OptimalNormalBasis::has_type_two_basis(257));
}

#[test]
fn in_the_optimal_normal_basis_the_unit_is_all_ones_and_squaring_is_a_cyclic_shift_right() {
    for m in OptimalNormalBasis::STANDARD_DEGREES {
        let field = BinaryField::optimal_normal(m).unwrap();
        let all_ones = (BigUint::from(1u32) << m) - 1u32;
        assert_eq!(all_ones, field.one().to_biguint(), "5.3, m = {m}");

        let v = TestRandom::new(u64::from(m)).integer(m);
        let rotated_right = (&v >> 1u32) | ((&v & BigUint::from(1u32)) << (m - 1)); // В.4
        assert_eq!(rotated_right, element(&field, &v).square().to_biguint(), "m = {m}");
    }
}

/// An independent reference: Gaussian normal basis multiplication of ANSI X9.62 / IEEE 1363 (A.3.8), written over
/// bit arrays without any of the tricks of the library.
fn reference_onb_multiply(m: u32, x: &BigUint, y: &BigUint) -> BigUint {
    let (m, p) = (m as usize, 2 * m as usize + 1);
    // f[k] = i where k = ±2^i mod p
    let mut f = vec![0usize; p];
    let mut w = 1usize;
    for i in 0..m {
        f[w] = i;
        f[p - w] = i;
        w = 2 * w % p;
    }

    // u[i] = the coefficient of x^(2^i): the leftmost bit of the standard representation is i = 0 (5.3).
    let mut u: Vec<u8> = (0..m).map(|i| u8::from(x.bit((m - 1 - i) as u64))).collect();
    let mut v: Vec<u8> = (0..m).map(|i| u8::from(y.bit((m - 1 - i) as u64))).collect();
    let mut c = vec![0u8; m];
    for coefficient in c.iter_mut() {
        *coefficient = (1..=p - 2).fold(0, |sum, j| sum ^ (u[f[j + 1]] & v[f[p - j]]));
        u.rotate_left(1);
        v.rotate_left(1);
    }

    let mut r = BigUint::default();
    for (i, &coefficient) in c.iter().enumerate() {
        if coefficient != 0 {
            r.set_bit((m - 1 - i) as u64, true);
        }
    }
    r
}

#[test]
fn optimal_normal_multiplication_matches_the_x962_reference() {
    for m in OptimalNormalBasis::STANDARD_DEGREES {
        let field = BinaryField::optimal_normal(m).unwrap();
        let mut random = TestRandom::new(u64::from(m) * 7);
        for _ in 0..3 {
            let (a, b) = (random.integer(m), random.integer(m));
            let product = &element(&field, &a) * &element(&field, &b);
            assert_eq!(reference_onb_multiply(m, &a, &b), product.to_biguint(), "m = {m}");
        }
    }
}

#[test]
fn optimal_normal_multiplication_of_every_pair_of_basis_elements_matches_the_reference() {
    // Exhaustive check of the folding logic in small fields: 2m + 1 = 11, 19, 23, 47.
    for m in [5u32, 9, 11, 23] {
        if !OptimalNormalBasis::has_type_two_basis(m) {
            continue;
        }
        let field = BinaryField::optimal_normal(m).unwrap();
        for i in 0..m {
            for j in 0..m {
                let (a, b) = (BigUint::from(1u32) << i, BigUint::from(1u32) << j);
                let product = &element(&field, &a) * &element(&field, &b);
                assert_eq!(
                    reference_onb_multiply(m, &a, &b),
                    product.to_biguint(),
                    "m = {m}, i = {i}, j = {j}"
                );
            }
        }
    }
}

#[test]
fn separately_created_fields_interoperate() {
    let f1 = BinaryField::optimal_normal(173).unwrap();
    let f2 = BinaryField::optimal_normal(173).unwrap();
    assert_eq!(f1, f2);
    let hex = |field: &BinaryField, text: &str| FieldElement::from_hex(field, text).unwrap();
    assert_eq!(hex(&f1, "ABCDEF"), hex(&f2, "ABCDEF"));
    assert_eq!(
        (&hex(&f1, "1234") * &hex(&f1, "5678")).to_biguint(),
        (&hex(&f1, "1234") * &hex(&f2, "5678")).to_biguint()
    );

    let p1 = BinaryField::polynomial(163, 3, 6, 7).unwrap();
    assert_ne!(p1, BinaryField::polynomial(163, 1, 2, 8).unwrap());
    let mixed = std::panic::catch_unwind(|| &hex(&p1, "1") * &hex(&f1, "1"));
    assert!(mixed.is_err(), "elements of different fields must not multiply");
}

#[test]
fn a_value_wider_than_m_bits_is_not_an_element() {
    let field = BinaryField::optimal_normal(173).unwrap();
    let too_wide = BigUint::from(1u32) << 173u32;
    assert_eq!(
        Err(ua_gf2m::FieldElementError::TooWide { m: 173 }),
        FieldElement::from_biguint(&field, &too_wide)
    );
}

#[test]
fn bytes_and_hex_are_the_standard_representation() {
    let field = BinaryField::polynomial(163, 3, 6, 7).unwrap();
    let a = FieldElement::from_hex(&field, "5FF6108462A2DC8210AB403925E638A19C1455D21").unwrap();
    assert_eq!("5FF6108462A2DC8210AB403925E638A19C1455D21", a.to_hex());
    let bytes = a.to_bytes();
    assert_eq!(21, bytes.len());
    assert_eq!(a, FieldElement::from_bytes(&field, &bytes).unwrap());
    assert!(a.test_bit(0));
    assert!(!a.test_bit(1));
}

#[test]
fn fields_outside_the_supported_shapes_are_refused() {
    assert_eq!(
        Err(FieldError::DegreeTooSmall(1)),
        BinaryField::optimal_normal(1).map(|_| ())
    );
    assert_eq!(
        Err(FieldError::NoTypeTwoBasis(163)),
        BinaryField::optimal_normal(163).map(|_| ())
    );
    assert_eq!(
        Err(FieldError::DegreeTooLarge {
            m: 521,
            max: ua_gf2m::MAX_DEGREE
        }),
        BinaryField::polynomial(521, 32, 0, 0).map(|_| ())
    );
    assert_eq!(
        Err(FieldError::ExponentOutOfRange { m: 163, k: 0 }),
        BinaryField::polynomial(163, 0, 0, 0).map(|_| ())
    );
    assert_eq!(
        Err(FieldError::PentanomialNotOrdered { k: 3, j: 7, l: 6 }),
        BinaryField::polynomial(163, 3, 7, 6).map(|_| ())
    );
    assert_eq!(
        Err(FieldError::MiddleTermsTooHigh { m: 163, highest: 150 }),
        BinaryField::polynomial(163, 150, 0, 0).map(|_| ())
    );
}

#[test]
fn the_change_of_basis_is_a_field_isomorphism() {
    let polynomial = BinaryField::polynomial(173, 1, 2, 10).unwrap();
    let normal = BinaryField::optimal_normal(173).unwrap();
    let converter = ua_gf2m::BasisConverter::new(&polynomial, &normal, &mut rand_core::OsRng);
    assert_eq!(polynomial.one(), converter.to_polynomial(&normal.one()));
    let mut random = TestRandom::new(173);
    for _ in 0..5 {
        let a = element(&normal, &random.integer(173));
        let b = element(&normal, &random.integer(173));
        assert_eq!(a, converter.to_normal(&converter.to_polynomial(&a)));
        assert_eq!(
            converter.to_polynomial(&(&a * &b)),
            &converter.to_polynomial(&a) * &converter.to_polynomial(&b)
        );
    }
}
