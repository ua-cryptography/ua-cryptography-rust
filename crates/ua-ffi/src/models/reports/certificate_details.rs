use serde::Serialize;

use crate::models::reports::AlgorithmRow;

/// What a certificate says, as the reports show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertificateDetails {
    /// The subject, e.g. "CN=Name, O=Organization, C=UA".
    pub subject: String,
    /// The issuer.
    pub issuer: String,
    /// The serial number, upper-case hex without leading zeros.
    pub serial: String,
    /// The start of the validity period, UTC, ISO 8601.
    pub valid_from: String,
    /// The end of the validity period, UTC, ISO 8601.
    pub valid_to: String,
    /// The algorithm the issuer signed the certificate with.
    pub signature_algorithm: AlgorithmRow,
    /// basicConstraints cA.
    pub is_ca: bool,
    /// The OCSP responders of authorityInfoAccess.
    pub ocsp_urls: Vec<String>,
    /// The caIssuers addresses of authorityInfoAccess.
    pub ca_issuer_urls: Vec<String>,
    /// The time-stamping services of subjectInfoAccess.
    pub time_stamp_urls: Vec<String>,
}
