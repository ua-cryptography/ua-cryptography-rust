use serde::Serialize;

use crate::models::reports::SignatureSummary;

/// The verification of a signed file: the verdict and a summary per signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationSummary {
    /// The format recognised, e.g. "ASiC-E".
    pub format: String,
    /// Every signature holds and none failed a check.
    pub is_valid: bool,
    /// The signatures, the container's structure report excluded.
    pub signature_count: usize,
    /// The checks that ended with a warning.
    pub warning_count: usize,
    /// The checks that failed.
    pub failure_count: usize,
    /// When the verification was made, UTC, ISO 8601.
    pub verified_at: String,
    /// The names of the files the signatures cover.
    pub signed_files: Vec<String>,
    /// The structure report of a container first, then each signature.
    pub signatures: Vec<SignatureSummary>,
}
