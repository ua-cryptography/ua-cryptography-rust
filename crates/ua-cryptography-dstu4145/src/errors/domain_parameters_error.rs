use std::fmt;

/// Why domain parameters (DSTU 4145-2002, section 7) refuse to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainParametersError {
    /// The base point lies on another curve.
    BasePointOnAnotherCurve,
    /// The order n is zero.
    ZeroOrder,
}

impl fmt::Display for DomainParametersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BasePointOnAnotherCurve => write!(f, "the base point belongs to another curve"),
            Self::ZeroOrder => write!(f, "the order n of the base point must be positive"),
        }
    }
}

impl std::error::Error for DomainParametersError {}
