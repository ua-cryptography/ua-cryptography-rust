use crate::c_abi::types::UaCurveBasis;

/// A recommended curve of DSTU 4145-2002: its table and the degree m of its field.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UaCurve {
    /// Table Г.1 or Г.2.
    pub basis: UaCurveBasis,
    /// The degree m of GF(2^m).
    pub m: u32,
}
