use wasm_bindgen::prelude::wasm_bindgen;

use ua_cryptography_operations::models::simple_types::CurveBasis;

/// The table of DSTU 4145-2002, Appendix Г a curve comes from.
#[wasm_bindgen(js_name = CurveBasis)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveBasisJs {
    /// Table Г.1, polynomial basis: m = 163, 167, 173, 179, 191, 233, 257, 307, 367, 431.
    Polynomial = 0,
    /// Table Г.2, optimal normal basis: m = 173, 179, 191, 233, 431.
    OptimalNormal = 1,
}

impl From<CurveBasisJs> for CurveBasis {
    fn from(basis: CurveBasisJs) -> Self {
        match basis {
            CurveBasisJs::Polynomial => Self::Polynomial,
            CurveBasisJs::OptimalNormal => Self::OptimalNormal,
        }
    }
}
