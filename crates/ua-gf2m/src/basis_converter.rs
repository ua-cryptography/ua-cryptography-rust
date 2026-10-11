use num_bigint::BigUint;
use num_traits::One;
use rand_core::{CryptoRng, RngCore};

use crate::gf2_poly::{self, MAX_WORDS, Words};
use crate::{BinaryCurve, BinaryField, CurvePoint, FieldBasis, FieldElement, PointError};

/// The change of basis between a polynomial basis and the optimal normal basis of the same GF(2^m)
/// (DSTU 4145-2002, В.6).
///
/// В.6 builds the transition matrix from a root of the normal polynomial. Here the root x is found without root
/// finding: for a type 2 basis x = g + 1/g with g a primitive p-th root of unity, p = 2m + 1, and such g is
/// z^((2^(2m) − 1)/p) for a random z of GF(2^(2m)) = GF(2^m)\[u\]/(u² + u + 1) (irreducible because m is odd).
/// The roots x, x², …, x^(2^(m−1)) cyclically shift the normal representation of every element; the root with the
/// smallest polynomial representation is taken, so the conversion is deterministic.
#[derive(Debug, Clone)]
pub struct BasisConverter {
    polynomial: BinaryField,
    normal: BinaryField,
    normal_element: FieldElement,
    /// Row i: x^(2^i) in the polynomial basis (standard words).
    normal_to_polynomial: Vec<Words>,
    /// Row k: t^k in the normal basis, as the coefficients of x^(2^i).
    polynomial_to_normal: Vec<Words>,
}

impl BasisConverter {
    /// The converter between `polynomial` and `normal`; the randomness only finds the root, the result is the same.
    ///
    /// # Panics
    ///
    /// When the first field is not in a polynomial basis, the second not in an optimal normal one, or their degrees
    /// differ.
    pub fn new(polynomial: &BinaryField, normal: &BinaryField, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        assert!(
            matches!(polynomial.basis(), FieldBasis::Polynomial(_)),
            "the first field must be in a polynomial basis"
        );
        assert!(
            matches!(normal.basis(), FieldBasis::OptimalNormal(_)),
            "the second field must be in an optimal normal basis"
        );
        assert_eq!(polynomial.m(), normal.m(), "both fields must have the same degree");
        let normal_element = find_normal_element(polynomial, rng);
        converter_with_root(polynomial, normal, normal_element)
    }

    /// The field in the polynomial basis.
    pub fn polynomial(&self) -> &BinaryField {
        &self.polynomial
    }

    /// The field in the normal basis.
    pub fn normal(&self) -> &BinaryField {
        &self.normal
    }

    /// The generator x of the normal basis, expressed in the polynomial basis.
    pub fn normal_element(&self) -> &FieldElement {
        &self.normal_element
    }

    /// Normal basis → polynomial basis.
    ///
    /// # Panics
    ///
    /// When the element is not of the normal field.
    pub fn to_polynomial(&self, a: &FieldElement) -> FieldElement {
        assert!(a.field() == &self.normal, "the element belongs to another field");
        let m = self.normal.m() as usize;
        let standard = a.to_biguint();
        let mut result: Words = [0; MAX_WORDS];
        for j in 0..m {
            // Standard bit j of the normal representation is the coefficient of x^(2^(m−1−j)).
            if standard.bit(j as u64) {
                gf2_poly::xor_into(&mut result, &self.normal_to_polynomial[m - 1 - j]);
            }
        }
        FieldElement::from_words(&self.polynomial, result)
    }

    /// Polynomial basis → normal basis.
    ///
    /// # Panics
    ///
    /// When the element is not of the polynomial field.
    pub fn to_normal(&self, a: &FieldElement) -> FieldElement {
        assert!(a.field() == &self.polynomial, "the element belongs to another field");
        let m = self.polynomial.m() as usize;
        let standard = a.to_biguint();
        let mut coefficients: Words = [0; MAX_WORDS]; // bit i: the coefficient of x^(2^i)
        for k in 0..m {
            if standard.bit(k as u64) {
                gf2_poly::xor_into(&mut coefficients, &self.polynomial_to_normal[k]);
            }
        }
        let mut result: Words = [0; MAX_WORDS];
        for i in 0..m {
            if gf2_poly::test_bit(&coefficients, i) {
                gf2_poly::flip_bit(&mut result, m - 1 - i);
            }
        }
        FieldElement::from_words(&self.normal, self.normal.internal_from_standard(&result))
    }

    /// The curve in the other basis; the coefficient A ∈ {0, 1} is preserved.
    ///
    /// # Panics
    ///
    /// When the curve is over neither field of this converter.
    pub fn convert_curve(&self, curve: &BinaryCurve) -> BinaryCurve {
        let (target, b) = if curve.field() == &self.polynomial {
            (&self.normal, self.to_normal(curve.b()))
        } else if curve.field() == &self.normal {
            (&self.polynomial, self.to_polynomial(curve.b()))
        } else {
            panic!("the curve is defined over neither field of this converter");
        };
        let a = if curve.a().is_zero() {
            target.zero()
        } else {
            target.one()
        };
        match BinaryCurve::new(target, &a, &b) {
            Ok(converted) => converted,
            Err(error) => unreachable!("an isomorphism keeps A in {{0, 1}} and B ≠ 0: {error}"),
        }
    }

    /// The point on `target`, the image of its curve (see [`convert_curve`](Self::convert_curve)).
    pub fn convert_point(&self, point: &CurvePoint, target: &BinaryCurve) -> Result<CurvePoint, PointError> {
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            return Ok(target.infinity());
        };
        if point.curve().field() == &self.polynomial {
            CurvePoint::new(target, self.to_normal(x), self.to_normal(y))
        } else {
            CurvePoint::new(target, self.to_polynomial(x), self.to_polynomial(y))
        }
    }

    /// The converter over another root of the normal polynomial, chosen so that `polynomial_value` maps exactly to
    /// `normal_value` (e.g. to align table Г.1 with table Г.2 by the coefficient B); absent when the values are not
    /// Frobenius conjugates under any change of basis.
    pub fn find_aligned(&self, polynomial_value: &FieldElement, normal_value: &FieldElement) -> Option<Self> {
        let shift = Self::find_frobenius_shift(&self.to_normal(polynomial_value), normal_value)?;
        // With the root x' = x^(2^s) the normal coordinates rotate: ToNormal'(a) = ToNormal(a)^(2^−s).
        // We need ToNormal'(v) = ToNormal(v)^(2^shift), so x' = x^(2^(m − shift)).
        let m = self.polynomial.m();
        let root = self.normal_element.square_times((m - shift) % m);
        Some(converter_with_root(&self.polynomial, &self.normal, root))
    }

    /// j such that b = a^(2^j) (in the normal basis: b is a cyclic shift right of a by j).
    pub fn find_frobenius_shift(a: &FieldElement, b: &FieldElement) -> Option<u32> {
        let mut x = a.clone();
        for j in 0..a.field().m() {
            if &x == b {
                return Some(j);
            }
            x = x.square();
        }
        None
    }

    /// The normal polynomial of В.2: q(t) = 1, p(t) = t + 1, then m − 1 times r = q, q = p, p = t q + r;
    /// the coefficient of t^i is bit i.
    pub fn calculate_normal_polynomial(m: u32) -> BigUint {
        let mut q = BigUint::one();
        let mut p = BigUint::from(0b11u32); // t + 1
        for _ in 1..m {
            let r = q;
            q = p;
            p = (&q << 1u32) ^ r;
        }
        p
    }
}

/// The converter whose normal basis is generated by `normal_element`.
fn converter_with_root(polynomial: &BinaryField, normal: &BinaryField, normal_element: FieldElement) -> BasisConverter {
    let m = polynomial.m() as usize;
    let mut normal_to_polynomial = Vec::with_capacity(m);
    let mut power = normal_element.clone();
    for _ in 0..m {
        normal_to_polynomial.push(*power.words()); // the polynomial basis keeps the standard form
        power = power.square();
    }
    assert!(
        power == normal_element,
        "x^(2^m) ≠ x: the normal element is not in GF(2^m)"
    );
    let polynomial_to_normal = invert_matrix(&normal_to_polynomial, m);
    BasisConverter {
        polynomial: polynomial.clone(),
        normal: normal.clone(),
        normal_element,
        normal_to_polynomial,
        polynomial_to_normal,
    }
}

/// x = g + 1/g for g of order p = 2m + 1, the conjugate with the smallest integer representation.
fn find_normal_element(field: &BinaryField, rng: &mut (impl RngCore + CryptoRng)) -> FieldElement {
    let m = field.m();
    let p = 2 * m + 1;
    let exponent = ((BigUint::one() << (2 * m)) - 1u32) / p;
    loop {
        let z = QuadraticElement {
            low: FieldElement::random(field, rng),
            high: FieldElement::random(field, rng),
        };
        if z.is_zero() {
            continue;
        }
        let g = z.pow(&exponent);
        if g.is_one() {
            continue; // an element of order exactly p is needed (p is prime)
        }
        let sum = g.add(&g.pow(&BigUint::from(p - 1))); // g + 1/g
        assert!(sum.high.is_zero(), "g + 1/g is not in GF(2^m)");

        // A deterministic choice among the conjugates.
        let mut best = sum.low.clone();
        let mut x = sum.low;
        for _ in 1..m {
            x = x.square();
            if x.to_biguint() < best.to_biguint() {
                best = x.clone();
            }
        }
        return best;
    }
}

/// Gauss–Jordan inversion of an m × m matrix over GF(2) given by rows (bit k of row i = M[i, k]).
fn invert_matrix(rows: &[Words], m: usize) -> Vec<Words> {
    let mut a = rows.to_vec();
    let mut inverse: Vec<Words> = (0..m)
        .map(|i| {
            let mut row: Words = [0; MAX_WORDS];
            gf2_poly::flip_bit(&mut row, i);
            row
        })
        .collect();

    for column in 0..m {
        let pivot = (column..m).find(|&row| gf2_poly::test_bit(&a[row], column));
        let Some(pivot) = pivot else {
            panic!("the conjugates of x are linearly dependent: not a normal basis");
        };
        a.swap(column, pivot);
        inverse.swap(column, pivot);
        let (pivot_row, pivot_inverse) = (a[column], inverse[column]);
        for row in 0..m {
            if row != column && gf2_poly::test_bit(&a[row], column) {
                gf2_poly::xor_into(&mut a[row], &pivot_row);
                gf2_poly::xor_into(&mut inverse[row], &pivot_inverse);
            }
        }
    }

    // The same row operations turned [R | I] into [I | R⁻¹]; row k of R⁻¹ holds t^k in the normal basis.
    inverse
}

/// The element low + high·u of GF(2^(2m)) = GF(2^m)\[u\]/(u² + u + 1).
struct QuadraticElement {
    low: FieldElement,
    high: FieldElement,
}

impl QuadraticElement {
    fn is_zero(&self) -> bool {
        self.low.is_zero() && self.high.is_zero()
    }

    fn is_one(&self) -> bool {
        self.low.is_one() && self.high.is_zero()
    }

    fn add(&self, other: &Self) -> Self {
        Self {
            low: &self.low + &other.low,
            high: &self.high + &other.high,
        }
    }

    /// (a0 + a1 u)(b0 + b1 u) = a0 b0 + a1 b1 + (a0 b1 + a1 b0 + a1 b1) u, since u² = u + 1.
    fn multiply(&self, other: &Self) -> Self {
        let t0 = &self.low * &other.low;
        let t1 = &self.high * &other.high;
        let t2 = &(&self.low + &self.high) * &(&other.low + &other.high);
        Self {
            low: &t0 + &t1,
            high: &t2 + &t0,
        }
    }

    fn pow(&self, exponent: &BigUint) -> Self {
        let field = self.low.field();
        let mut result = Self {
            low: field.one(),
            high: field.zero(),
        };
        for i in (0..exponent.bits()).rev() {
            result = result.multiply(&result);
            if exponent.bit(i) {
                result = result.multiply(self);
            }
        }
        result
    }
}
