use std::fmt;

/// Why a field GF(2^m) refuses to exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    /// m < 2.
    DegreeTooSmall(u32),
    /// m is above the largest degree the fixed-size arithmetic holds.
    DegreeTooLarge {
        /// The degree asked for.
        m: u32,
        /// The largest supported degree.
        max: u32,
    },
    /// The exponent k of the reduction polynomial is not in 0 < k < m.
    ExponentOutOfRange {
        /// The extension degree.
        m: u32,
        /// The exponent asked for.
        k: u32,
    },
    /// A pentanomial needs 0 < k < j < l < m.
    PentanomialNotOrdered {
        /// The smallest exponent asked for.
        k: u32,
        /// The middle exponent asked for.
        j: u32,
        /// The largest exponent asked for.
        l: u32,
    },
    /// The word-level reduction needs the middle terms below m − 64.
    MiddleTermsTooHigh {
        /// The extension degree.
        m: u32,
        /// The highest exponent below m.
        highest: u32,
    },
    /// GF(2^m) has no optimal normal basis of type 2 (DSTU 4145-2002, В.2).
    NoTypeTwoBasis(u32),
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DegreeTooSmall(m) => write!(f, "the field degree m = {m} is below 2"),
            Self::DegreeTooLarge { m, max } => write!(f, "the field degree m = {m} is above the supported {max}"),
            Self::ExponentOutOfRange { m, k } => write!(f, "the exponent k = {k} must satisfy 0 < k < m = {m}"),
            Self::PentanomialNotOrdered { k, j, l } => {
                write!(
                    f,
                    "a pentanomial requires 0 < k < j < l < m, got k = {k}, j = {j}, l = {l}"
                )
            }
            Self::MiddleTermsTooHigh { m, highest } => {
                write!(
                    f,
                    "the reduction polynomial's middle term t^{highest} must be below m - 64 = {}",
                    m - 64
                )
            }
            Self::NoTypeTwoBasis(m) => write!(f, "GF(2^{m}) has no optimal normal basis of type 2"),
        }
    }
}

impl std::error::Error for FieldError {}
