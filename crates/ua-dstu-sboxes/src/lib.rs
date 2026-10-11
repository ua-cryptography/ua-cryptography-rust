//! The four S-boxes π0..π3 that DSTU 7564:2014 (Kupyna) and DSTU 7624:2014 (Kalyna) share, and their inverses.
//!
//! - [`PI`]: π0..π3; row `r` of a state uses `PI[r % 4]`.
//! - [`INVERSE_PI`]: their inverses, computed at compile time.

#![forbid(unsafe_code)]

mod inverse_pi;
mod pi;

pub use inverse_pi::INVERSE_PI;
pub use pi::PI;
