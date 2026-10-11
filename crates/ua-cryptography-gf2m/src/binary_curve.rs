mod montgomery_ladder;

use std::fmt;
use std::sync::Arc;

use num_bigint::BigUint;
use num_traits::Zero;
use rand_core::{CryptoRng, RngCore};

use crate::gf2_poly::Words;
use crate::{BinaryField, CurveError, CurvePoint, FieldElement, PointError};

const BYTE_BITS: usize = 8;

/// The elliptic curve y² + xy = x³ + Ax² + B over GF(2^m), A ∈ {0, 1}, B ≠ 0 (DSTU 4145-2002, 5.4), shared by its
/// points: cloning is cheap.
///
/// Every formula is written in field operations, so the same code serves both bases. The methods that take points
/// panic when a point belongs to another curve: only buggy code mixes them.
#[derive(Clone)]
pub struct BinaryCurve {
    shape: Arc<CurveShape>,
}

struct CurveShape {
    field: BinaryField,
    a: FieldElement,
    b: FieldElement,
    /// √B in the internal representation, for the doubling of the Montgomery ladder.
    sqrt_b: Words,
}

impl BinaryCurve {
    /// The curve with the coefficients A and B of `field`.
    ///
    /// # Panics
    ///
    /// When A or B belongs to another field.
    pub fn new(field: &BinaryField, a: &FieldElement, b: &FieldElement) -> Result<Self, CurveError> {
        assert!(
            a.field() == field && b.field() == field,
            "the curve coefficients must belong to the given field"
        );
        if !a.is_zero() && !a.is_one() {
            return Err(CurveError::CoefficientANotZeroOrOne);
        }
        if b.is_zero() {
            return Err(CurveError::ZeroCoefficientB);
        }
        let sqrt_b = *b.sqrt().words();
        Ok(Self {
            shape: Arc::new(CurveShape {
                field: field.clone(),
                a: a.clone(),
                b: b.clone(),
                sqrt_b,
            }),
        })
    }

    /// The curve with A = 0 or 1 (the unit of the field) and B given by its standard representation.
    pub fn from_biguint(field: &BinaryField, a: u32, b: &BigUint) -> Result<Self, CurveError> {
        let a = match a {
            0 => field.zero(),
            1 => field.one(),
            _ => return Err(CurveError::CoefficientANotZeroOrOne),
        };
        let b = FieldElement::from_biguint(field, b).map_err(CurveError::CoefficientB)?;
        Self::new(field, &a, &b)
    }

    /// The field GF(2^m) of the coordinates.
    pub fn field(&self) -> &BinaryField {
        &self.shape.field
    }

    /// The coefficient A: zero or the unit.
    pub fn a(&self) -> &FieldElement {
        &self.shape.a
    }

    /// The coefficient B.
    pub fn b(&self) -> &FieldElement {
        &self.shape.b
    }

    /// The point at infinity O, the neutral element of the group.
    pub fn infinity(&self) -> CurvePoint {
        CurvePoint::infinity(self)
    }

    /// y² + xy = x³ + Ax² + B.
    pub fn is_on_curve(&self, p: &CurvePoint) -> bool {
        let Some((x, y)) = p.coordinates() else {
            return true;
        };
        let x2 = x.square();
        let left = &y.square() + &(x * y);
        let right = &(&(&x2 * x) + &(self.a() * &x2)) + self.b();
        left == right
    }

    /// −P = (x, x + y).
    pub fn negate(&self, p: &CurvePoint) -> CurvePoint {
        self.assert_own(p);
        match p.coordinates() {
            None => p.clone(),
            Some((x, y)) => CurvePoint::from_trusted_coordinates(self, x.clone(), x + y),
        }
    }

    /// P + Q in affine coordinates (DSTU 4145-2002, В.8).
    pub fn add(&self, p: &CurvePoint, q: &CurvePoint) -> CurvePoint {
        self.assert_own(p);
        self.assert_own(q);
        let (Some((x1, y1)), Some((x2, y2))) = (p.coordinates(), q.coordinates()) else {
            return if p.is_infinity() { q.clone() } else { p.clone() };
        };
        if x1 == x2 {
            // Either Q = P (doubling) or Q = −P (the sum is O).
            return if y1 == y2 { self.double(p) } else { self.infinity() };
        }

        // The second formula of В.8 has a misprint "(x_P + y_Q)" in the denominator; it must be x_P + x_Q.
        let x_sum = x1 + x2;
        let lambda = &(y1 + y2) / &x_sum;
        let x3 = &(&(&lambda.square() + &lambda) + &x_sum) + self.a();
        let y3 = &(&(&lambda * &(x1 + &x3)) + &x3) + y1;
        CurvePoint::from_trusted_coordinates(self, x3, y3)
    }

    /// 2P in affine coordinates (DSTU 4145-2002, В.8).
    pub fn double(&self, p: &CurvePoint) -> CurvePoint {
        self.assert_own(p);
        let Some((x, y)) = p.coordinates() else {
            return p.clone();
        };
        if x.is_zero() {
            return self.infinity(); // the only point of order 2: (0, √B)
        }
        let x2 = x.square();
        let x_doubled = &x2 + &(self.b() / &x2);
        let y_doubled = &(&x2 + &(&(x + &(y / x)) * &x_doubled)) + &x_doubled;
        CurvePoint::from_trusted_coordinates(self, x_doubled, y_doubled)
    }

    /// kP by the Montgomery ladder in López–Dahab projective x-only coordinates: each bit of k costs the same
    /// 6 multiplications and 5 squarings, with one inversion at the end.
    pub fn multiply(&self, p: &CurvePoint, k: &BigUint) -> CurvePoint {
        self.assert_own(p);
        let Some((x, _)) = p.coordinates() else {
            return self.infinity();
        };
        if k.is_zero() {
            return self.infinity();
        }
        if x.is_zero() {
            // A point of order 2.
            return if k.bit(0) { p.clone() } else { self.infinity() };
        }
        montgomery_ladder::multiply(self, p, k, k.bits())
    }

    /// kP for a point P of known order with a fixed number of ladder steps, so that the running time does not reveal
    /// the bit length of a secret scalar (private keys, the nonce e).
    ///
    /// # Panics
    ///
    /// When P = O or the order is zero.
    pub fn multiply_fixed_length(&self, p: &CurvePoint, k: &BigUint, order: &BigUint) -> CurvePoint {
        self.assert_own(p);
        assert!(
            !p.is_infinity() && !order.is_zero(),
            "a finite point of known order is required"
        );
        let k = k % order;
        if k.is_zero() {
            return self.infinity();
        }

        // k' = k + n or k + 2n has exactly L(n) + 1 bits and k'P = kP.
        let bits = order.bits() + 1;
        let mut extended = &k + order;
        if extended.bits() < bits {
            extended += order;
        }
        montgomery_ladder::multiply(self, p, &extended, bits)
    }

    /// kP by the plain double-and-add of В.8 in affine coordinates: the reference for the ladder.
    pub fn multiply_double_and_add(&self, p: &CurvePoint, k: &BigUint) -> CurvePoint {
        let mut q = self.infinity();
        for i in (0..k.bits()).rev() {
            q = self.double(&q);
            if k.bit(i) {
                q = self.add(&q, p);
            }
        }
        q
    }

    /// A random point of the curve (DSTU 4145-2002, 6.8).
    pub fn random_point(&self, rng: &mut (impl RngCore + CryptoRng)) -> CurvePoint {
        let field = self.field();
        loop {
            let u = FieldElement::random(field, rng);
            let u2 = u.square();
            let w = &(&(&u2 * &u) + &(self.a() * &u2)) + self.b(); // w = u³ + Au² + B
            let (solutions, z) = field.solve_quadratic(u.words(), w.words());
            if solutions > 0 {
                return CurvePoint::from_trusted_coordinates(self, u, FieldElement::from_words(field, z));
            }
        }
    }

    /// Point compression (6.9): the least significant bit of x_P replaced by tr(y_P / x_P), as the standard
    /// representation; 0 stands for O and for the point with x_P = 0.
    pub fn compress(&self, p: &CurvePoint) -> Result<BigUint, PointError> {
        self.assert_own(p);
        let Some((x, y)) = p.coordinates().filter(|(x, _)| !x.is_zero()) else {
            return Ok(BigUint::zero());
        };
        let mut compressed = x.to_biguint();
        compressed.set_bit(0, (y / x).trace() == 1);
        if compressed.is_zero() {
            // x = 1 as a bit string with tr(y/x) = 0 compresses to 0, which 6.10 decodes as (0, √B): a gap in the
            // standard. Such a point (probability about 2^−m) cannot be represented compressed.
            return Err(PointError::NoCompressedForm);
        }
        Ok(compressed)
    }

    /// [`compress`](Self::compress) as big-endian bytes, ⌈m / 8⌉ of them.
    pub fn compress_to_bytes(&self, p: &CurvePoint) -> Result<Vec<u8>, PointError> {
        let digits = self.compress(p)?.to_bytes_be();
        let length = (self.field().m() as usize).div_ceil(BYTE_BITS);
        let mut bytes = vec![0u8; length.saturating_sub(digits.len())];
        bytes.extend_from_slice(&digits);
        Ok(bytes)
    }

    /// Point decompression (6.10); refuses a value that encodes no point of this curve.
    pub fn decompress(&self, compressed: &BigUint) -> Result<CurvePoint, PointError> {
        let field = self.field();
        if compressed.is_zero() {
            return Ok(CurvePoint::from_trusted_coordinates(
                self,
                field.zero(),
                self.b().sqrt(),
            ));
        }

        let k = u8::from(compressed.bit(0));
        let mut x_value = compressed.clone();
        x_value.set_bit(0, false);
        let mut x = FieldElement::from_biguint(field, &x_value)?;
        let trace_a = u8::from(!self.a().is_zero());
        if x.trace() != trace_a {
            x_value.set_bit(0, true);
            x = FieldElement::from_biguint(field, &x_value)?;
        }
        if x.is_zero() {
            return Err(PointError::NotOnCurve);
        }

        let x2 = x.square();
        let right = &(&(&x2 * &x) + &(self.a() * &x2)) + self.b();
        let v = &right / &x2;
        let (solutions, z) = field.solve_quadratic(field.one_words(), v.words());
        if solutions == 0 {
            return Err(PointError::NotOnCurve);
        }
        let z = FieldElement::from_words(field, z);
        let y = if z.trace() == k {
            &z * &x
        } else {
            &(&z + &field.one()) * &x
        };
        Ok(CurvePoint::from_trusted_coordinates(self, x, y))
    }

    /// [`decompress`](Self::decompress) of big-endian bytes.
    pub fn decompress_from_bytes(&self, bytes: &[u8]) -> Result<CurvePoint, PointError> {
        self.decompress(&BigUint::from_bytes_be(bytes))
    }

    pub(crate) fn sqrt_b_words(&self) -> &Words {
        &self.shape.sqrt_b
    }

    /// # Panics
    ///
    /// When the point belongs to another curve.
    fn assert_own(&self, p: &CurvePoint) {
        assert!(
            Arc::ptr_eq(&self.shape, &p.curve().shape) || self == p.curve(),
            "the point belongs to another curve"
        );
    }
}

impl PartialEq for BinaryCurve {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shape, &other.shape)
            || (self.field() == other.field() && self.a() == other.a() && self.b() == other.b())
    }
}

impl Eq for BinaryCurve {}

impl fmt::Display for BinaryCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a_term = if self.a().is_zero() { "" } else { "x^2 + " };
        write!(
            f,
            "y^2 + xy = x^3 + {a_term}{} over {}",
            self.b().to_hex(),
            self.field()
        )
    }
}

impl fmt::Debug for BinaryCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BinaryCurve({self})")
    }
}
