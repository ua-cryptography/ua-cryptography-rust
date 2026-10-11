//! Curves over the public API, on the curve of the worked example Б.1 and on curves built for one test.

mod common;

use common::TestRandom;
use num_bigint::BigUint;
use ua_gf2m::{BinaryCurve, BinaryField, CurveError, CurvePoint, FieldElement, PointError, parse_hex};

const B1_B: &str = "5FF6108462A2DC8210AB403925E638A19C1455D21";
const B1_PX: &str = "72D867F93A93AC27DF9FF01AFFE74885C8C540420";
const B1_PY: &str = "0224A9C3947852B97C5599D5F4AB81122ADC3FD9B";
const B1_N: &str = "400000000000000000002BEC12BE2262D39BCF14D";

fn b1_curve() -> (BinaryCurve, CurvePoint, BigUint) {
    let field = BinaryField::polynomial(163, 3, 6, 7).unwrap();
    let curve = BinaryCurve::from_biguint(&field, 1, &parse_hex(B1_B).unwrap()).unwrap();
    let p = CurvePoint::from_hex(&curve, B1_PX, B1_PY).unwrap();
    (curve, p, parse_hex(B1_N).unwrap())
}

#[test]
fn the_ladder_matches_double_and_add_and_the_operators() {
    let (curve, p, n) = b1_curve();
    assert!(curve.multiply(&p, &n).is_infinity());
    let mut random = TestRandom::new(163);
    for _ in 0..4 {
        let k = random.integer(163);
        let expected = curve.multiply_double_and_add(&p, &k);
        assert_eq!(expected, curve.multiply(&p, &k));
        assert_eq!(expected, &p * &k);
        assert_eq!(expected, curve.multiply_fixed_length(&p, &k, &n));
    }
    assert_eq!(p.twice(), &p + &p);
    assert!((&p - &p).is_infinity());
    assert_eq!(-&p, p.negate());
}

#[test]
fn compressed_points_round_trip_as_integers_and_octets() {
    // 6.10 recovers x from tr(x) = tr(A), which holds in the subgroup of odd order n, so the points are multiples
    // of the base point.
    let (curve, p, _) = b1_curve();
    let mut random = TestRandom::new(21);
    for _ in 0..8 {
        let q = curve.multiply(&p, &random.integer(160));
        let compressed = curve.compress(&q).unwrap();
        assert_eq!(q, curve.decompress(&compressed).unwrap());
        let octets = curve.compress_to_bytes(&q).unwrap();
        assert_eq!(21, octets.len());
        assert_eq!(q, curve.decompress_from_bytes(&octets).unwrap());
    }
    assert_eq!(BigUint::default(), curve.compress(&curve.infinity()).unwrap());
}

#[test]
fn the_point_with_x_one_and_trace_zero_has_no_compressed_form() {
    // 6.9 maps x = 1 (as a bit string) with tr(y/x) = 0 to 0, which 6.10 reads as (0, √B). With y = zx the curve
    // y² + xy = x³ + B becomes z² + z = x + B/x², solvable when its trace is 0: pick such a B.
    let field = BinaryField::optimal_normal(173).unwrap();
    let x = FieldElement::from_biguint(&field, &BigUint::from(1u32)).unwrap();
    let x_squared = x.square();
    let (b, w) = (2u32..)
        .map(|value| FieldElement::from_biguint(&field, &BigUint::from(value)).unwrap())
        .map(|b| {
            let w = &x + &(&b / &x_squared);
            (b, w)
        })
        .find(|(_, w)| w.trace() == 0)
        .unwrap();
    let curve = BinaryCurve::new(&field, &field.zero(), &b).unwrap();
    let z = w.half_trace();
    let z = if z.trace() == 0 { z } else { &z + &field.one() }; // tr(y/x) = tr(z) = 0
    let point = CurvePoint::new(&curve, x.clone(), &z * &x).unwrap();
    assert_eq!(Err(PointError::NoCompressedForm), curve.compress(&point));
}

#[test]
fn curves_with_a_bad_coefficient_are_refused() {
    let field = BinaryField::optimal_normal(173).unwrap();
    let b = BigUint::from(7u32);
    assert_eq!(
        Err(CurveError::CoefficientANotZeroOrOne),
        BinaryCurve::from_biguint(&field, 2, &b).map(|_| ())
    );
    assert_eq!(
        Err(CurveError::ZeroCoefficientB),
        BinaryCurve::from_biguint(&field, 0, &BigUint::default()).map(|_| ())
    );
    let a = FieldElement::from_biguint(&field, &BigUint::from(1u32)).unwrap(); // the bit string 1, not the unit
    assert_eq!(
        Err(CurveError::CoefficientANotZeroOrOne),
        BinaryCurve::new(&field, &a, &field.one()).map(|_| ())
    );
}
