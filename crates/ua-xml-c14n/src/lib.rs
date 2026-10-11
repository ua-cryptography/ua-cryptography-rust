//! Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 (with or without comments) over `roxmltree`.
//!
//! - [`DocumentText`] decodes XML bytes (UTF-8 or UTF-16, line ends normalized) and parses them safely: DTDs are
//!   refused, so no entity is expanded and nothing external is read ([`DocumentError`]).
//! - [`canonicalize`] writes the canonical form of a whole document or of one element in its document context
//!   (inherited namespaces and, for inclusive C14N, inherited `xml:*` attributes), with an InclusiveNamespaces
//!   prefix list and an excluded subtree (the enveloped-signature transform). [`Algorithm`] names the method by URI.
//! - [`escape_text`] / [`escape_attribute`] escape text for XML built as text; [`looks_like_xml`] sniffs input.
//! - `roxmltree` is re-exported, so callers name the same `Document` and `Node` types.

#![forbid(unsafe_code)]

mod algorithm;
mod canonicalizer;
mod document_error;
mod document_text;
mod escape;

pub use algorithm::Algorithm;
pub use document_text::DocumentText;

pub use document_error::DocumentError;

pub use canonicalizer::canonicalize;
pub use document_text::looks_like_xml;
pub use escape::escape_attribute;
pub use escape::escape_text;
pub use roxmltree;
