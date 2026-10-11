use std::fmt;

use crate::FieldElementError;

/// Why a curve y² + xy = x³ + Ax² + B refuses to exist (DSTU 4145-2002, 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurveError {
    /// A is neither 0 nor 1.
    CoefficientANotZeroOrOne,
    /// B = 0.
    ZeroCoefficientB,
    /// B is not an element of the field.
    CoefficientB(FieldElementError),
}

impl fmt::Display for CurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CoefficientANotZeroOrOne => write!(f, "coefficient A must be 0 or 1 (DSTU 4145-2002, 5.4)"),
            Self::ZeroCoefficientB => write!(f, "coefficient B must be non-zero"),
            Self::CoefficientB(error) => write!(f, "coefficient B: {error}"),
        }
    }
}

impl std::error::Error for CurveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CoefficientB(error) => Some(error),
            Self::CoefficientANotZeroOrOne | Self::ZeroCoefficientB => None,
        }
    }
}
