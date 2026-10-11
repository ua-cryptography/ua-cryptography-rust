use serde::Serialize;

use crate::models::reports::{AlgorithmRow, CertificateDetails, CheckRow, ReferenceRow};

/// The verification of one signature, or of an ASiC container's structure (titled "container").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureSummary {
    /// What was verified, e.g. "CAdES signature".
    pub title: String,
    /// The format and level found, e.g. "XAdES-B-LT" or "CAdES-T".
    pub level: Option<String>,
    /// "detached" or "enveloped".
    pub packaging: Option<String>,
    /// The signature algorithm.
    pub signature_algorithm: Option<AlgorithmRow>,
    /// The hash the signature is computed over.
    pub digest_algorithm: Option<AlgorithmRow>,
    /// The signing time the signer claims, UTC, ISO 8601.
    pub signing_time: Option<String>,
    /// The time of the signature time-stamp, when present and valid.
    pub timestamp_time: Option<String>,
    /// The time the certificates were validated at: the time-stamp, else the claimed time, else now.
    pub validation_time: Option<String>,
    /// No check failed.
    pub is_valid: bool,
    /// A check ended with a warning.
    pub has_warnings: bool,
    /// The signer's certificate, when found.
    pub signer: Option<CertificateDetails>,
    /// What the signature covers.
    pub references: Vec<ReferenceRow>,
    /// Every check in the order made.
    pub checks: Vec<CheckRow>,
}
