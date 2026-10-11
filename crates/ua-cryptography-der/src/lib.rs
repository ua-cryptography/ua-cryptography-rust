//! DER for the Ukrainian PKI: a reader that keeps the exact bytes of every element, a writer, and PEM.
//!
//! - [`Asn1Node`] reads DER and the BER forms CMS uses (indefinite lengths, constructed strings) without copying:
//!   every element is a slice of the input, so signatures are checked over the bytes as received. Malformed input,
//!   high tag numbers and nesting deeper than 64 levels are refused with [`DerError`].
//! - The writer is a set of small functions, each returning one complete DER element: [`sequence`], [`set_of`]
//!   (sorted), [`integer`], [`object_identifier`], [`named_bits`], [`x509_time`], [`explicit`], [`implicit`]….
//! - [`encode_oid`] / [`decode_oid`] convert dotted-decimal object identifiers; [`decode_pem`] / [`encode_pem`]
//!   handle PEM (RFC 7468).
//! - [`tag`] holds the identifier octets.

#![forbid(unsafe_code)]

mod asn1_node;
mod character_string;
mod errors;
mod oid;
mod pem;
pub mod tag;
mod time_text;
mod writer;

pub use asn1_node::Asn1Node;

pub use errors::DerError;
pub use errors::OidError;
pub use errors::PemError;

pub use oid::decode_oid;
pub use oid::encode_oid;
pub use pem::decode_pem;
pub use pem::encode_pem;
pub use writer::algorithm_identifier;
pub use writer::bit_string;
pub use writer::boolean;
pub use writer::encode;
pub use writer::explicit;
pub use writer::generalized_time;
pub use writer::ia5_string;
pub use writer::implicit;
pub use writer::integer;
pub use writer::integer_from_i64;
pub use writer::integer_from_unsigned;
pub use writer::named_bits;
pub use writer::null;
pub use writer::object_identifier;
pub use writer::octet_string;
pub use writer::printable_string;
pub use writer::sequence;
pub use writer::set_of;
pub use writer::utc_time;
pub use writer::utf8_string;
pub use writer::x509_time;
