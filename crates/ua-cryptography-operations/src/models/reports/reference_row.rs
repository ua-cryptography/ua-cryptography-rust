use serde::Serialize;

use crate::models::reports::AlgorithmRow;

/// What a signature covers: a XAdES reference, or "content" in CAdES.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferenceRow {
    /// The reference URI, or "content".
    pub name: String,
    /// The hash of the digest.
    pub digest_algorithm: AlgorithmRow,
    /// The digest, upper-case hex.
    pub digest: String,
}
