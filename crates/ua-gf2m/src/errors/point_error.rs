use std::fmt;

use crate::FieldElementError;

/// Why a point is refused: on creation, compression (6.9) or decompression (6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointError {
    /// A coordinate or a compressed value is not an element of the field.
    Coordinate(FieldElementError),
    /// The coordinates or the compressed value describe no point of the curve.
    NotOnCurve,
    /// 6.9 maps this point (x = 1, tr(y/x) = 0) to 0, which 6.10 decodes as another point.
    NoCompressedForm,
}

impl fmt::Display for PointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinate(error) => write!(f, "point coordinate: {error}"),
            Self::NotOnCurve => write!(f, "the point does not lie on the curve"),
            Self::NoCompressedForm => write!(f, "this point has no unambiguous compressed form (6.9 maps it to 0)"),
        }
    }
}

impl std::error::Error for PointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coordinate(error) => Some(error),
            Self::NotOnCurve | Self::NoCompressedForm => None,
        }
    }
}

impl From<FieldElementError> for PointError {
    fn from(error: FieldElementError) -> Self {
        Self::Coordinate(error)
    }
}
