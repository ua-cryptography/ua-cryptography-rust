//! The change of basis (В.6) over the degrees of table 2, and table Г.2 as table Г.1 in the normal basis.

mod common;

use common::TestRandom;
use rand_core::OsRng;
use ua_cryptography_dstu4145::{
    DomainParameters, NORMAL_DEGREES, POLYNOMIAL_DEGREES, Signer, get_optimal_normal_curve, get_polynomial_curve,
    get_polynomial_field,
};
use ua_cryptography_gf2m::{BasisConverter, BinaryField, FieldElement, OptimalNormalBasis};

fn create_converter(m: u32) -> BasisConverter {
    let polynomial = get_polynomial_field(m).unwrap();
    let normal = BinaryField::optimal_normal(m).unwrap();
    BasisConverter::new(&polynomial, &normal, &mut OsRng)
}

fn random_element(field: &BinaryField, random: &mut TestRandom) -> FieldElement {
    FieldElement::from_biguint(field, &random.integer(field.m())).unwrap()
}

/// The degrees with a curve in both Г.1 and Г.2.
fn common_degrees() -> Vec<u32> {
    NORMAL_DEGREES
        .iter()
        .copied()
        .filter(|m| POLYNOMIAL_DEGREES.contains(m))
        .collect()
}

#[test]
fn the_conversion_is_a_field_isomorphism() {
    for m in OptimalNormalBasis::STANDARD_DEGREES {
        let c = create_converter(m);
        let mut random = TestRandom::new(u64::from(m));
        assert_eq!(c.polynomial().one(), c.to_polynomial(&c.normal().one()), "m = {m}");
        for _ in 0..5 {
            let a = random_element(c.normal(), &mut random);
            let b = random_element(c.normal(), &mut random);
            assert_eq!(a, c.to_normal(&c.to_polynomial(&a)), "m = {m}");
            assert_eq!(
                c.to_polynomial(&(&a * &b)),
                &c.to_polynomial(&a) * &c.to_polynomial(&b),
                "m = {m}"
            );
            assert_eq!(
                c.to_polynomial(&(&a + &b)),
                &c.to_polynomial(&a) + &c.to_polynomial(&b),
                "m = {m}"
            );

            let u = random_element(c.polynomial(), &mut random);
            assert_eq!(u, c.to_polynomial(&c.to_normal(&u)), "m = {m}");
        }
    }
}

#[test]
fn the_normal_element_is_a_root_of_the_normal_polynomial() {
    // В.2: the normal polynomial built by the recurrence has x as a root.
    for m in OptimalNormalBasis::STANDARD_DEGREES {
        let c = create_converter(m);
        let p = BasisConverter::calculate_normal_polynomial(m);
        assert_eq!(u64::from(m), p.bits() - 1, "m = {m}");
        let mut acc = c.polynomial().zero();
        for i in (0..=m).rev() {
            acc = &acc * c.normal_element();
            if p.bit(u64::from(i)) {
                acc = &acc + &c.polynomial().one();
            }
        }
        assert!(acc.is_zero(), "m = {m}");
    }
}

#[test]
fn the_conversion_is_deterministic() {
    let (a, b) = (create_converter(173), create_converter(173));
    assert_eq!(a.normal_element().to_biguint(), b.normal_element().to_biguint());
}

/// The curves of table Г.2 are the curves of table Г.1 in the normal basis: after a change of basis (with a suitable
/// root of the normal polynomial) the coefficient B coincides bit for bit, which also confirms the bit order of the
/// normal representation for every curve of Г.2.
#[test]
fn table_g2_is_table_g1_in_the_normal_basis() {
    for m in common_degrees() {
        let pb = get_polynomial_curve(m).unwrap();
        let onb = get_optimal_normal_curve(m).unwrap();
        assert_eq!(pb.n(), onb.n(), "m = {m}");

        let c = BasisConverter::new(pb.field(), onb.field(), &mut OsRng).find_aligned(pb.curve().b(), onb.curve().b());
        let c = c.unwrap();
        let converted = c.convert_curve(pb.curve());
        assert_eq!(onb.curve().b(), converted.b(), "m = {m}");
        assert_eq!(onb.curve().a().is_zero(), converted.a().is_zero(), "m = {m}");

        // The converted base point of Г.1 is a valid generator of the same subgroup on the Г.2 curve.
        let g = c.convert_point(pb.base_point(), onb.curve()).unwrap();
        assert!(onb.curve().multiply(&g, onb.n()).is_infinity(), "m = {m}");
    }
}

#[test]
fn scalar_multiplication_commutes_with_the_change_of_basis() {
    for m in common_degrees() {
        let pb = get_polynomial_curve(m).unwrap();
        let c = BasisConverter::new(pb.field(), get_optimal_normal_curve(m).unwrap().field(), &mut OsRng);
        let onb_curve = c.convert_curve(pb.curve());
        let g_onb = c.convert_point(pb.base_point(), &onb_curve).unwrap();

        let mut random = TestRandom::new(u64::from(m));
        for _ in 0..3 {
            let k = random.integer(m) % pb.n();
            let expected = c
                .convert_point(&pb.curve().multiply(pb.base_point(), &k), &onb_curve)
                .unwrap();
            assert_eq!(expected, onb_curve.multiply(&g_onb, &k), "m = {m}");
        }
    }
}

#[test]
fn keys_convert_but_signatures_are_bound_to_the_basis() {
    let pb = get_polynomial_curve(233).unwrap();
    let c = BasisConverter::new(pb.field(), &BinaryField::optimal_normal(233).unwrap(), &mut OsRng);
    let onb_curve = c.convert_curve(pb.curve());
    let onb_base_point = c.convert_point(pb.base_point(), &onb_curve).unwrap();
    let onb = DomainParameters::new(&onb_curve, &onb_base_point, pb.n()).unwrap();
    assert_eq!(Ok(()), onb.validate());

    let mut pb_signer = Signer::new(&pb);
    let onb_signer = Signer::new(&onb);
    let key = pb_signer.generate_key_pair();
    let q = c.convert_point(&key.public_key, &onb_curve).unwrap();
    assert_eq!(
        onb_signer.calculate_public_key(&key.private_key).unwrap(),
        q,
        "Q = −dP in either basis"
    );

    let h = random_element(pb.field(), &mut TestRandom::new(1));
    let presignature = pb_signer.generate_presignature();
    let (r, s) = pb_signer.sign(&key.private_key, &h, &presignature).unwrap().unwrap();
    assert!(pb_signer.verify(&key.public_key, &h, &r, &s));

    // R = sP + rQ is the same point, but r is cut from the bit string of h·x_R (5.8), which depends on the basis.
    assert!(!onb_signer.verify(&q, &c.to_normal(&h), &r, &s));
}

#[test]
fn values_that_are_not_conjugates_have_no_aligned_converter() {
    let c = create_converter(173);
    let one_in_pb = c.polynomial().one();
    let zero_in_onb = c.normal().zero();
    assert!(c.find_aligned(&one_in_pb, &zero_in_onb).is_none());
    assert_eq!(
        None,
        BasisConverter::find_frobenius_shift(&c.normal().one(), &zero_in_onb)
    );
}
