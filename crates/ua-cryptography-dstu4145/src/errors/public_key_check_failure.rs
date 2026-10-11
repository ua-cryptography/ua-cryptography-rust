use std::fmt;

/// The condition of DSTU 4145-2002, 10.1 that a public key fails; the clause leads the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyCheckFailure {
    /// 10.1.1: Q belongs to another curve.
    OnAnotherCurve,
    /// 10.1.2: Q = O.
    AtInfinity,
    /// 10.1.3: Q is not on the curve.
    NotOnCurve,
    /// 10.1.4: nQ ≠ O.
    OrderMismatch,
}

impl fmt::Display for PublicKeyCheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::OnAnotherCurve => "10.1.1: Q belongs to another curve",
            Self::AtInfinity => "10.1.2: Q = O",
            Self::NotOnCurve => "10.1.3: Q does not lie on the curve",
            Self::OrderMismatch => "10.1.4: nQ ≠ O",
        };
        f.write_str(text)
    }
}

impl std::error::Error for PublicKeyCheckFailure {}
