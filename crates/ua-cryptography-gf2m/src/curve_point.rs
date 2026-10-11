use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

use num_bigint::BigUint;

use crate::{BinaryCurve, FieldElement, PointError};

/// An immutable point of a [`BinaryCurve`] in affine coordinates, or the point at infinity O.
///
/// Every point lies on its curve: the constructors check it. Points support `&p + &q`, `&p - &q`, `-&p` and
/// `&p * &k`; the operators panic when the points belong to different curves.
#[derive(Clone)]
pub struct CurvePoint {
    curve: BinaryCurve,
    affine: Option<(FieldElement, FieldElement)>,
}

impl CurvePoint {
    /// The point (x, y), checked to lie on the curve.
    pub fn new(curve: &BinaryCurve, x: FieldElement, y: FieldElement) -> Result<Self, PointError> {
        let field = curve.field();
        if x.field() != field || y.field() != field {
            return Err(PointError::NotOnCurve);
        }
        let point = Self::from_trusted_coordinates(curve, x, y);
        if !curve.is_on_curve(&point) {
            return Err(PointError::NotOnCurve);
        }
        Ok(point)
    }

    /// The point whose coordinates have the standard representations x and y (DSTU 4145-2002, 5.3).
    pub fn from_biguint(curve: &BinaryCurve, x: &BigUint, y: &BigUint) -> Result<Self, PointError> {
        let field = curve.field();
        Self::new(
            curve,
            FieldElement::from_biguint(field, x)?,
            FieldElement::from_biguint(field, y)?,
        )
    }

    /// The point whose coordinates have the standard representations in hex.
    pub fn from_hex(curve: &BinaryCurve, x: &str, y: &str) -> Result<Self, PointError> {
        let field = curve.field();
        Self::new(
            curve,
            FieldElement::from_hex(field, x)?,
            FieldElement::from_hex(field, y)?,
        )
    }

    /// The curve the point belongs to.
    pub fn curve(&self) -> &BinaryCurve {
        &self.curve
    }

    /// The affine x, absent for O.
    pub fn x(&self) -> Option<&FieldElement> {
        self.affine.as_ref().map(|(x, _)| x)
    }

    /// The affine y, absent for O.
    pub fn y(&self) -> Option<&FieldElement> {
        self.affine.as_ref().map(|(_, y)| y)
    }

    /// Whether this is the point at infinity O.
    pub fn is_infinity(&self) -> bool {
        self.affine.is_none()
    }

    /// −P = (x, x + y).
    pub fn negate(&self) -> Self {
        self.curve.negate(self)
    }

    /// 2P.
    pub fn twice(&self) -> Self {
        self.curve.double(self)
    }

    /// kP by the Montgomery ladder.
    pub fn multiply(&self, k: &BigUint) -> Self {
        self.curve.multiply(self, k)
    }

    pub(crate) fn infinity(curve: &BinaryCurve) -> Self {
        Self {
            curve: curve.clone(),
            affine: None,
        }
    }

    /// A point whose coordinates satisfy the curve equation by construction.
    pub(crate) fn from_trusted_coordinates(curve: &BinaryCurve, x: FieldElement, y: FieldElement) -> Self {
        Self {
            curve: curve.clone(),
            affine: Some((x, y)),
        }
    }

    /// The coordinates of a finite point.
    pub(crate) fn coordinates(&self) -> Option<(&FieldElement, &FieldElement)> {
        self.affine.as_ref().map(|(x, y)| (x, y))
    }
}

impl PartialEq for CurvePoint {
    fn eq(&self, other: &Self) -> bool {
        self.curve == other.curve && self.affine == other.affine
    }
}

impl Eq for CurvePoint {}

impl fmt::Display for CurvePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.affine {
            None => f.write_str("O"),
            Some((x, y)) => write!(f, "({x}, {y})"),
        }
    }
}

impl fmt::Debug for CurvePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CurvePoint{self}")
    }
}

impl Add for &CurvePoint {
    type Output = CurvePoint;

    fn add(self, other: &CurvePoint) -> CurvePoint {
        self.curve.add(self, other)
    }
}

impl Add for CurvePoint {
    type Output = CurvePoint;

    fn add(self, other: CurvePoint) -> CurvePoint {
        &self + &other
    }
}

impl Sub for &CurvePoint {
    type Output = CurvePoint;

    fn sub(self, other: &CurvePoint) -> CurvePoint {
        self.curve.add(self, &other.negate())
    }
}

impl Sub for CurvePoint {
    type Output = CurvePoint;

    fn sub(self, other: CurvePoint) -> CurvePoint {
        &self - &other
    }
}

impl Neg for &CurvePoint {
    type Output = CurvePoint;

    fn neg(self) -> CurvePoint {
        self.negate()
    }
}

impl Neg for CurvePoint {
    type Output = CurvePoint;

    fn neg(self) -> CurvePoint {
        self.negate()
    }
}

impl Mul<&BigUint> for &CurvePoint {
    type Output = CurvePoint;

    fn mul(self, k: &BigUint) -> CurvePoint {
        self.multiply(k)
    }
}
