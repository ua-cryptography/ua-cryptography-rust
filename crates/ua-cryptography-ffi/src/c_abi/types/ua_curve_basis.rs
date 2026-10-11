/// The table of DSTU 4145-2002, Appendix Г a curve comes from: `UA_CURVE_BASIS_POLYNOMIAL` (Г.1) or
/// `UA_CURVE_BASIS_OPTIMAL_NORMAL` (Г.2).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaCurveBasis(pub u32);

/// Table Г.1, polynomial basis: m = 163, 167, 173, 179, 191, 233, 257, 307, 367, 431.
pub const UA_CURVE_BASIS_POLYNOMIAL: UaCurveBasis = UaCurveBasis(0);

/// Table Г.2, optimal normal basis: m = 173, 179, 191, 233, 431.
pub const UA_CURVE_BASIS_OPTIMAL_NORMAL: UaCurveBasis = UaCurveBasis(1);
