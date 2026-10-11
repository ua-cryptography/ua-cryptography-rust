use std::fmt;

/// The first condition of DSTU 4145-2002, 8.1–8.3 that domain parameters fail; the clause leads the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterCheckFailure {
    /// 8.1.1: the degree of a polynomial basis is not listed in table 1.
    DegreeNotInTable1,
    /// 8.1.2: the reduction polynomial is not irreducible.
    PolynomialReducible,
    /// 8.1.3: the degree of an optimal normal basis is not listed in table 2.
    DegreeNotInTable2,
    /// 8.2.2: A is neither 0 nor 1.
    CoefficientANotZeroOrOne,
    /// 8.2.3: B = 0.
    ZeroCoefficientB,
    /// 8.2.4: n is not an odd prime.
    OrderNotOddPrime,
    /// 8.2.5: n is below max(2^160, 4 √(2^m)).
    OrderTooSmall,
    /// 8.2.6: 2^(mk) = 1 mod n for some k ≤ 32.
    MovConditionFails,
    /// 8.3.2: P = O.
    BasePointAtInfinity,
    /// 8.3.3: P is not on the curve.
    BasePointNotOnCurve,
    /// 8.3.4: nP ≠ O.
    BasePointOrderMismatch,
}

impl fmt::Display for ParameterCheckFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::DegreeNotInTable1 => "8.1.1: the degree is not listed in table 1",
            Self::PolynomialReducible => "8.1.2: the reduction polynomial is not irreducible",
            Self::DegreeNotInTable2 => "8.1.3: the degree is not listed in table 2",
            Self::CoefficientANotZeroOrOne => "8.2.2: A must be 0 or 1",
            Self::ZeroCoefficientB => "8.2.3: B must be non-zero",
            Self::OrderNotOddPrime => "8.2.4: n is not an odd prime",
            Self::OrderTooSmall => "8.2.5: n is too small",
            Self::MovConditionFails => "8.2.6: the Menezes–Okamoto–Vanstone condition fails",
            Self::BasePointAtInfinity => "8.3.2: P = O",
            Self::BasePointNotOnCurve => "8.3.3: P does not lie on the curve",
            Self::BasePointOrderMismatch => "8.3.4: nP ≠ O",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ParameterCheckFailure {}
