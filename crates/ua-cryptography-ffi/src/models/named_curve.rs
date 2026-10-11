use crate::models::simple_types::CurveBasis;

/// A recommended curve of DSTU 4145-2002, Appendix Г: its table and its field degree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamedCurve {
    /// Table Г.1 or Г.2.
    pub basis: CurveBasis,
    /// The degree m of GF(2^m).
    pub m: u32,
}
