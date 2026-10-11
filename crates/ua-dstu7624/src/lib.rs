//! DSTU 7624:2014 "Kalyna" block cipher and its modes, translated from BouncyCastle Java 1.86.
//!
//! - [`Kalyna`]: the block cipher (128-, 256- or 512-bit blocks, a key of one or two blocks).
//! - [`BlockSize`]: the three block lengths.
//! - Modes over whole messages: [`Ecb`], [`Cbc`], [`Cfb`], [`Ofb`], [`Ctr`], [`Cmac`], [`Ccm`], [`Gcm`], [`Gmac`],
//!   [`Xts`], [`KeyWrap`].
//! - [`SetupError`]: why a cipher or a mode refuses its parameters; [`CipherFailure`]: why one message is refused.

#![forbid(unsafe_code)]

mod block_size;
mod errors;
mod kalyna;
mod modes;
mod round_functions;
mod utils;

pub use block_size::BlockSize;
pub use kalyna::Kalyna;
pub use modes::Cbc;
pub use modes::Ccm;
pub use modes::Cfb;
pub use modes::Cmac;
pub use modes::Ctr;
pub use modes::Ecb;
pub use modes::Gcm;
pub use modes::Gmac;
pub use modes::KeyWrap;
pub use modes::Ofb;
pub use modes::Xts;

pub use errors::CipherFailure;
pub use errors::SetupError;
