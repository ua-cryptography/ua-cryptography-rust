//! The curve arithmetic over the recommended curves: the ladder against В.8, edge cases, the group law, compression.

mod common;

use common::{TestRandom, get_recommended_curve, recommended_curves};
use num_bigint::BigUint;
use rand_core::OsRng;
use ua_cryptography_gf2m::{CurvePoint, PointError};

fn big(value: u32) -> BigUint {
    BigUint::from(value)
}

#[test]
fn the_ladder_matches_the_affine_double_and_add() {
    for (basis, m) in recommended_curves() {
        let p = get_recommended_curve(basis, m);
        let c = p.curve();
        let mut random = TestRandom::new(u64::from(m));
        for _ in 0..2 {
            let k = random.integer(p.n().bits() as u32);
            assert_eq!(
                c.multiply_double_and_add(p.base_point(), &k),
                c.multiply(p.base_point(), &k),
                "{basis} {m}"
            );
        }
    }
}

#[test]
fn scalar_multiplication_handles_the_edge_cases() {
    for (basis, m) in recommended_curves() {
        let p = get_recommended_curve(basis, m);
        let (c, g, n) = (p.curve(), p.base_point(), p.n());

        assert!(c.multiply(g, &big(0)).is_infinity(), "{basis} {m}");
        assert_eq!(*g, c.multiply(g, &big(1)), "{basis} {m}");
        assert_eq!(c.double(g), c.multiply(g, &big(2)), "{basis} {m}");
        assert_eq!(c.add(&c.double(g), g), c.multiply(g, &big(3)), "{basis} {m}");
        assert_eq!(g.negate(), c.multiply(g, &(n - 1u32)), "{basis} {m}");
        assert!(c.multiply(g, n).is_infinity(), "{basis} {m}");
        assert_eq!(*g, c.multiply(g, &(n + 1u32)), "{basis} {m}");
        // A negative scalar is the multiple of the negated point: (−1)·G = 1·(−G).
        assert_eq!(g.negate(), c.multiply(&g.negate(), &big(1)), "{basis} {m}");
        assert!(c.multiply(&c.infinity(), &big(12345)).is_infinity(), "{basis} {m}");

        let mut random = TestRandom::new(u64::from(m) + 1);
        let scalars = [
            big(1),
            big(2),
            n - 1u32,
            n - 2u32,
            random.integer(100),
            random.integer(m) % n,
        ];
        for k in &scalars {
            assert_eq!(
                c.multiply(g, k),
                c.multiply_fixed_length(g, k, n),
                "{basis} {m}, k = {k}"
            );
        }
    }
}

#[test]
fn the_group_law_holds() {
    for (basis, m) in recommended_curves() {
        let p = get_recommended_curve(basis, m);
        let c = p.curve();
        let mut random = TestRandom::new(u64::from(m) + 2);
        let a = c.multiply(p.base_point(), &random.integer(64));
        let b = c.multiply(p.base_point(), &random.integer(64));
        let d = c.random_point(&mut OsRng);

        assert!(
            c.is_on_curve(&a) && c.is_on_curve(&b) && c.is_on_curve(&d),
            "{basis} {m}"
        );
        assert_eq!(&a + &b, &b + &a, "{basis} {m}");
        assert_eq!(&(&a + &b) + &d, &a + &(&b + &d), "{basis} {m}");
        assert!((&a + &a.negate()).is_infinity(), "{basis} {m}");
        assert_eq!(a, &a + &c.infinity(), "{basis} {m}");
        assert_eq!(a.twice(), &a + &a, "{basis} {m}");
        assert!(c.is_on_curve(&(&a + &d)), "{basis} {m}");

        // (k1 + k2) P = k1 P + k2 P
        let (k1, k2) = (random.integer(m), random.integer(m));
        assert_eq!(
            c.multiply(&d, &(&k1 + &k2)),
            &c.multiply(&d, &k1) + &c.multiply(&d, &k2),
            "{basis} {m}"
        );
    }
}

#[test]
fn point_compression_round_trips() {
    for (basis, m) in recommended_curves() {
        let p = get_recommended_curve(basis, m);
        let c = p.curve();
        let mut random = TestRandom::new(u64::from(m) + 3);
        for _ in 0..3 {
            let q = c.multiply(p.base_point(), &(random.integer(m) % p.n()));
            let compressed = c.compress(&q).unwrap();
            assert_eq!(q, c.decompress(&compressed).unwrap(), "{basis} {m}");

            let octets = c.compress_to_bytes(&q).unwrap();
            assert_eq!((m as usize).div_ceil(8), octets.len(), "{basis} {m}");
            assert_eq!(q, c.decompress_from_bytes(&octets).unwrap(), "{basis} {m}");
        }
    }
}

#[test]
fn the_point_of_order_two_is_handled() {
    let p = ua_cryptography_dstu4145::get_polynomial_curve(163).unwrap();
    let c = p.curve();
    let t = CurvePoint::new(c, c.field().zero(), c.b().sqrt()).unwrap();
    assert!(c.double(&t).is_infinity());
    assert!(c.multiply(&t, &big(2)).is_infinity());
    assert_eq!(t, c.multiply(&t, &big(3)));
    assert_eq!(t, c.decompress(&big(0)).unwrap());
}

#[test]
fn points_outside_the_subgroup_pass_through_the_point_of_order_two() {
    // The curve order is h·n with h = 2 or 4. For a point R of even order, (order/2)·R is the point of order 2,
    // (0, √B), so the ladder must pass through and finish at x = 0 correctly.
    for (basis, m) in [("PB", 163), ("ONB", 173)] {
        let p = get_recommended_curve(basis, m);
        let c = p.curve();
        let t = CurvePoint::new(c, c.field().zero(), c.b().sqrt()).unwrap();
        for _ in 0..8 {
            let r = c.random_point(&mut OsRng);
            let nr = c.multiply(&r, p.n());
            assert_eq!(c.multiply_double_and_add(&r, p.n()), nr, "{basis} {m}");
            assert!(
                nr.is_infinity() || nr == t || c.double(&nr) == t || c.double(&nr).is_infinity(),
                "{basis} {m}"
            );
            assert!(c.multiply(&r, &(p.n() * 4u32)).is_infinity(), "{basis} {m}");
        }
    }
}

#[test]
fn a_point_off_the_curve_is_rejected() {
    let p = ua_cryptography_dstu4145::get_optimal_normal_curve(173).unwrap();
    let g = p.base_point();
    let x = g.x().unwrap().clone();
    assert_eq!(Err(PointError::NotOnCurve), CurvePoint::new(p.curve(), x.clone(), x));
}

#[test]
fn a_value_that_encodes_no_point_is_refused_by_decompression() {
    let p = ua_cryptography_dstu4145::get_polynomial_curve(163).unwrap();
    let c = p.curve();
    let too_wide = BigUint::from(1u32) << 170u32;
    assert!(matches!(c.decompress(&too_wide), Err(PointError::Coordinate(_))));
    // About half of the x values have no point; find one.
    let refused = (2u32..200).any(|x| c.decompress(&big(x)) == Err(PointError::NotOnCurve));
    assert!(refused, "some x in 2..200 must encode no point");
}
