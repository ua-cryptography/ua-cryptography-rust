use std::fmt;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand_core::{CryptoRng, OsRng, RngCore};
use ua_gf2m::{
    BinaryCurve, BinaryField, CurvePoint, FieldBasis, OptimalNormalBasis, STANDARD_PRIMALITY_ROUNDS, format_hex,
    integer_sqrt, is_probable_prime,
};

use crate::encoding::bit_length;
use crate::named_curves::POLYNOMIAL_TABLE;
use crate::{DomainParametersError, ParameterCheckFailure, PublicKeyCheckFailure};

const BYTE_BITS: u64 = 8;
/// L_D is a multiple of 16 (5.7).
const SIGNATURE_BITS_GRANULE: u64 = 16;
/// 8.2.5: n > 2^160 at least.
const MIN_ORDER_BITS: u32 = 160;
/// 6.13: 2^(mk) ≠ 1 mod n for k = 1..32.
const MOV_DEGREE_LIMIT: u32 = 32;

/// The general parameters of the signature (DSTU 4145-2002, section 7): the curve over its field, the base point P
/// and its prime order n. Cloning is cheap: the field and the curve are shared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainParameters {
    curve: BinaryCurve,
    base_point: CurvePoint,
    n: BigUint,
}

impl DomainParameters {
    /// The parameters (curve, P, n); the checks of section 8 are [`validate`](Self::validate).
    pub fn new(curve: &BinaryCurve, base_point: &CurvePoint, n: &BigUint) -> Result<Self, DomainParametersError> {
        if curve != base_point.curve() {
            return Err(DomainParametersError::BasePointOnAnotherCurve);
        }
        if n.is_zero() {
            return Err(DomainParametersError::ZeroOrder);
        }
        Ok(Self {
            curve: curve.clone(),
            base_point: base_point.clone(),
            n: n.clone(),
        })
    }

    /// The curve y² + xy = x³ + Ax² + B.
    pub fn curve(&self) -> &BinaryCurve {
        &self.curve
    }

    /// The field GF(2^m) of the curve.
    pub fn field(&self) -> &BinaryField {
        self.curve.field()
    }

    /// The base point P.
    pub fn base_point(&self) -> &CurvePoint {
        &self.base_point
    }

    /// The order n of the base point.
    pub fn n(&self) -> &BigUint {
        &self.n
    }

    /// The shortest admissible signature length: the least multiple of 16 that is ≥ 2 L(n) (5.7).
    pub fn minimum_signature_bits(&self) -> u32 {
        (2 * bit_length(&self.n)).div_ceil(SIGNATURE_BITS_GRANULE) as u32 * SIGNATURE_BITS_GRANULE as u32
    }

    /// 7.3: a base point for the curve, a random point P ≠ O, x_P ≠ 0, with nP = O.
    pub fn generate_base_point(curve: &BinaryCurve, n: &BigUint, rng: &mut (impl RngCore + CryptoRng)) -> CurvePoint {
        loop {
            let p = curve.random_point(rng);
            if p.x().is_none_or(|x| x.is_zero()) {
                continue;
            }
            if curve.multiply(&p, n).is_infinity() {
                return p;
            }
        }
    }

    /// The checks of 8.1–8.3: the first failed condition, if any. The Miller–Rabin bases come from the OS.
    pub fn validate(&self) -> Result<(), ParameterCheckFailure> {
        self.validate_field()?;
        self.validate_curve()?;

        // 8.3: the base point
        if self.base_point.is_infinity() {
            return Err(ParameterCheckFailure::BasePointAtInfinity);
        }
        if !self.curve.is_on_curve(&self.base_point) {
            return Err(ParameterCheckFailure::BasePointNotOnCurve);
        }
        if !self.curve.multiply(&self.base_point, &self.n).is_infinity() {
            return Err(ParameterCheckFailure::BasePointOrderMismatch);
        }
        Ok(())
    }

    /// 6.13: 2^(mk) ≠ 1 mod n for k = 1..32.
    pub fn check_mov_condition(n: &BigUint, m: u32) -> bool {
        let k = BigUint::from(2u32).modpow(&BigUint::from(m), n);
        let mut j = BigUint::one();
        for _ in 0..MOV_DEGREE_LIMIT {
            j = &j * &k % n;
            if j.is_one() {
                return false;
            }
        }
        true
    }

    /// 10.1: the checks of a public key.
    pub fn validate_public_key(&self, q: &CurvePoint) -> Result<(), PublicKeyCheckFailure> {
        if &self.curve != q.curve() {
            return Err(PublicKeyCheckFailure::OnAnotherCurve);
        }
        if q.is_infinity() {
            return Err(PublicKeyCheckFailure::AtInfinity);
        }
        if !self.curve.is_on_curve(q) {
            return Err(PublicKeyCheckFailure::NotOnCurve);
        }
        if !self.curve.multiply(q, &self.n).is_infinity() {
            return Err(PublicKeyCheckFailure::OrderMismatch);
        }
        Ok(())
    }

    /// 6.3: a random integer a with L(a) < L(n), i.e. of at most L(n) − 1 bits; the first generated bits become the
    /// most significant ones.
    pub fn generate_integer(&self, rng: &mut (impl RngCore + CryptoRng)) -> BigUint {
        let bits = bit_length(&self.n) - 1;
        let mut bytes = vec![0u8; bits.div_ceil(BYTE_BITS) as usize];
        rng.fill_bytes(&mut bytes);
        BigUint::from_bytes_be(&bytes) >> (BYTE_BITS * bytes.len() as u64 - bits)
    }

    /// 8.1: the field.
    fn validate_field(&self) -> Result<(), ParameterCheckFailure> {
        let m = self.field().m();
        match self.field().basis() {
            FieldBasis::Polynomial(basis) => {
                if !POLYNOMIAL_TABLE.iter().any(|&(degree, ..)| degree == m) {
                    return Err(ParameterCheckFailure::DegreeNotInTable1);
                }
                // 8.1.2 asks for a primitive polynomial; irreducibility is checked here (primitivity needs the
                // factorization of 2^m − 1). The polynomials of table 1 are primitive by the standard.
                if !basis.is_irreducible() {
                    return Err(ParameterCheckFailure::PolynomialReducible);
                }
            }
            FieldBasis::OptimalNormal(_) => {
                if !OptimalNormalBasis::STANDARD_DEGREES.contains(&m) {
                    return Err(ParameterCheckFailure::DegreeNotInTable2);
                }
            }
        }
        Ok(())
    }

    /// 8.2: the curve and the order of the base point.
    fn validate_curve(&self) -> Result<(), ParameterCheckFailure> {
        let a = self.curve.a();
        if !a.is_zero() && !a.is_one() {
            return Err(ParameterCheckFailure::CoefficientANotZeroOrOne);
        }
        if self.curve.b().is_zero() {
            return Err(ParameterCheckFailure::ZeroCoefficientB);
        }
        let n = &self.n;
        if !n.bit(0) || !is_probable_prime(n, STANDARD_PRIMALITY_ROUNDS, &mut OsRng) {
            return Err(ParameterCheckFailure::OrderNotOddPrime);
        }
        let m = self.field().m();
        let field_root = integer_sqrt(&(BigUint::one() << m));
        let bound = (BigUint::one() << MIN_ORDER_BITS).max((field_root + 1u32) * 4u32);
        if *n < bound {
            return Err(ParameterCheckFailure::OrderTooSmall);
        }
        if !Self::check_mov_condition(n, m) {
            return Err(ParameterCheckFailure::MovConditionFails);
        }
        Ok(())
    }
}

impl fmt::Display for DomainParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, n = {}", self.curve, format_hex(&self.n))
    }
}
