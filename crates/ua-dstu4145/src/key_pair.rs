use std::fmt;

use num_bigint::BigUint;
use ua_gf2m::CurvePoint;

/// A key pair: the private key d and the public key Q = −dP (DSTU 4145-2002, section 9).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyPair {
    /// d, 0 < d < n.
    pub private_key: BigUint,
    /// Q = −dP.
    pub public_key: CurvePoint,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}
