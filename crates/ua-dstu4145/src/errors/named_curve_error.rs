use std::fmt;

/// Why a recommended field or curve of DSTU 4145-2002 (table 1, Appendix Г) is not found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamedCurveError {
    /// Table 1 lists no polynomial of this degree.
    NotInTable1(u32),
    /// Table Г.1 has no curve of this degree.
    NotInTableG1(u32),
    /// Table Г.2 has no curve of this degree.
    NotInTableG2(u32),
    /// Table Г.1 has no curve with this index.
    IndexOutOfRange(usize),
}

impl fmt::Display for NamedCurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInTable1(m) => write!(f, "m = {m} is not listed in table 1"),
            Self::NotInTableG1(m) => write!(f, "table Г.1 has no curve over GF(2^{m})"),
            Self::NotInTableG2(m) => write!(f, "table Г.2 has no curve over GF(2^{m})"),
            Self::IndexOutOfRange(index) => write!(f, "table Г.1 has no curve number {index}"),
        }
    }
}

impl std::error::Error for NamedCurveError {}
