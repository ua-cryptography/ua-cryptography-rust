use std::fmt;

use num_bigint::BigUint;
use ua_gf2m::FieldElement;

/// The presignature (F_e, e) of DSTU 4145-2002, section 11: for one signature only.
#[derive(PartialEq, Eq)]
pub struct Presignature {
    /// The secret e, 0 < e < n.
    pub e: BigUint,
    /// F_e = x(eP).
    pub fe: FieldElement,
}

impl fmt::Debug for Presignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presignature")
            .field("e", &"<redacted>")
            .field("fe", &self.fe)
            .finish()
    }
}
