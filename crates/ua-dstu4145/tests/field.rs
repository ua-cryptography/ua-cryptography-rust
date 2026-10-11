//! The fields of table 1 and table 2: irreducibility, the field axioms, the standard representation, the trace.

mod common;

use common::TestRandom;
use num_bigint::BigUint;
use ua_dstu4145::{POLYNOMIAL_TABLE, get_polynomial_field};
use ua_gf2m::{BinaryField, FieldBasis, FieldElement, FieldElementError, OptimalNormalBasis};

/// Every field of table 1 (PB) and table 2 (ONB).
fn every_standard_field() -> Vec<BinaryField> {
    let polynomial = POLYNOMIAL_TABLE.iter().map(|&(m, ..)| get_polynomial_field(m).unwrap());
    let normal = OptimalNormalBasis::STANDARD_DEGREES
        .iter()
        .map(|&m| BinaryField::optimal_normal(m).unwrap());
    polynomial.chain(normal).collect()
}

fn random_element(field: &BinaryField, random: &mut TestRandom) -> FieldElement {
    FieldElement::from_biguint(field, &random.integer(field.m())).unwrap()
}

#[test]
fn the_polynomials_of_table_1_are_irreducible() {
    for &(m, ..) in &POLYNOMIAL_TABLE {
        let field = get_polynomial_field(m).unwrap();
        let FieldBasis::Polynomial(basis) = field.basis() else {
            panic!("table 1 builds polynomial bases")
        };
        assert!(basis.is_irreducible(), "m = {m}");
    }
}

#[test]
fn the_field_axioms_hold_in_every_standard_field() {
    for f in every_standard_field() {
        let mut random = TestRandom::new(u64::from(f.m()));
        for _ in 0..10 {
            let a = random_element(&f, &mut random);
            let b = random_element(&f, &mut random);
            let c = random_element(&f, &mut random);

            assert_eq!(&a * &b, &b * &a, "{f}");
            assert_eq!(&(&a * &b) * &c, &a * &(&b * &c), "{f}");
            assert_eq!(&a * &(&b + &c), &(&a * &b) + &(&a * &c), "{f}");
            assert_eq!(a, &a * &f.one(), "{f}");
            assert!((&a * &f.zero()).is_zero(), "{f}");
            assert_eq!(&a * &a, a.square(), "{f}");
            assert_eq!(a, a.square_times(f.m()), "{f}: a^(2^m) = a");
            if !a.is_zero() {
                assert_eq!(f.one(), &a * &a.invert(), "{f}");
            }
            assert_eq!(a, a.sqrt().square(), "{f}");
        }
    }
}

#[test]
fn the_standard_representation_round_trips() {
    for f in every_standard_field() {
        let mut random = TestRandom::new(u64::from(f.m()) + 1);
        for _ in 0..20 {
            let v = random.integer(f.m());
            assert_eq!(v, FieldElement::from_biguint(&f, &v).unwrap().to_biguint(), "{f}");
        }
        let too_wide = BigUint::from(1u32) << f.m();
        assert_eq!(
            Err(FieldElementError::TooWide { m: f.m() }),
            FieldElement::from_biguint(&f, &too_wide),
            "{f}"
        );
    }
}

#[test]
fn the_trace_is_zero_or_one_and_the_half_trace_solves_z_squared_plus_z() {
    for f in every_standard_field() {
        let mut random = TestRandom::new(u64::from(f.m()) + 2);
        assert_eq!(1, f.one().trace(), "{f}: m is odd");
        assert_eq!(0, f.zero().trace(), "{f}");
        for _ in 0..4 {
            let a = random_element(&f, &mut random);
            // For tr(v) = 0 the half-trace solves z² + z = v.
            let v = if a.trace() == 0 { a } else { &a + &f.one() };
            let z = v.half_trace();
            assert_eq!(v, &z.square() + &z, "{f}");
        }
    }
}
