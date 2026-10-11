//! DSTU 7564:2014 "Kupyna" hash function at 256, 384 and 512 bits.
//!
//! - [`Kupyna`]: the hash, streaming or one-shot.
//! - [`HashSize`]: the three supported hash lengths.
//! - [`UnsupportedHashSizeError`]: a hash length other than 256, 384 or 512 bits.

#![forbid(unsafe_code)]

mod hash_size;
mod kupyna;
mod round_tables;
mod unsupported_hash_size_error;

pub use hash_size::HashSize;
pub use kupyna::Kupyna;

pub use unsupported_hash_size_error::UnsupportedHashSizeError;
