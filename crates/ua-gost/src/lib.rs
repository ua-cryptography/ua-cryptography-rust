//! GOST 28147-89 block cipher and GOST 34.311-95 hash, with any substitution table (DKE).
//!
//! - [`Gost28147`]: the block cipher in simple substitution mode on single 64-bit blocks.
//! - [`Gost34311`]: the hash function of DSTU 4145-2002 (6.2), streaming or one-shot.
//! - [`DEFAULT_DKE`]: DKE No. 1, the table used when a certificate names none.
//! - [`SubstitutionTableError`]: why a substitution table or a DKE is refused.

#![forbid(unsafe_code)]

mod default_dke;
mod gost28147;
mod gost34311;
mod substitution_table_error;

pub use gost28147::Gost28147;
pub use gost34311::Gost34311;

pub use substitution_table_error::SubstitutionTableError;

pub use default_dke::DEFAULT_DKE;
