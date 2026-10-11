use time::OffsetDateTime;

use crate::validation::{
    CertificatePath, CheckStatus, RevocationStatus, SignedObject, TimeStampDetails, VerificationCheck,
};
use crate::x509::Certificate;

/// The outcome of verifying one signature: every check made, the signer and the times found, and what the checks
/// were made on — algorithms, signed objects, time-stamps, certification paths and revocation statuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// What was verified, e.g. "CAdES signature" or "XAdES signature S-…".
    pub title: String,
    /// The format and level found, e.g. "CAdES-T, enveloped, DSTU 7564-256".
    pub format: Option<String>,
    /// The format and level alone, e.g. "XAdES-B-LT" or "CAdES-T".
    pub level: Option<String>,
    /// "detached" or "enveloped".
    pub packaging: Option<String>,
    /// The signature algorithm as the signature names it: an OID in CMS, a URI in XML-DSig.
    pub signature_algorithm: Option<String>,
    /// The OID of the hash the signature is computed over.
    pub digest_algorithm: Option<String>,
    /// The signer's certificate, when it was found.
    pub signer: Option<Certificate>,
    /// The signing time claimed by the signer (signingTime, xades:SigningTime).
    pub claimed_signing_time: Option<OffsetDateTime>,
    /// The time of the signature time-stamp, when present and valid.
    pub time_stamp_time: Option<OffsetDateTime>,
    /// Every check in the order made.
    pub checks: Vec<VerificationCheck>,
    /// What the signature covers.
    pub signed_objects: Vec<SignedObject>,
    /// The time-stamps found.
    pub time_stamps: Vec<TimeStampDetails>,
    /// The certification paths built.
    pub paths: Vec<CertificatePath>,
    /// The revocation statuses established.
    pub revocations: Vec<RevocationStatus>,
}

impl VerificationReport {
    /// An empty report titled `title`.
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_owned(),
            format: None,
            level: None,
            packaging: None,
            signature_algorithm: None,
            digest_algorithm: None,
            signer: None,
            claimed_signing_time: None,
            time_stamp_time: None,
            checks: Vec::new(),
            signed_objects: Vec::new(),
            time_stamps: Vec::new(),
            paths: Vec::new(),
            revocations: Vec::new(),
        }
    }

    /// True when there is a check and none failed (warnings allowed).
    pub fn is_valid(&self) -> bool {
        !self.checks.is_empty() && self.checks.iter().all(|check| check.status != CheckStatus::Failed)
    }

    /// True when a check ended with a warning.
    pub fn has_warnings(&self) -> bool {
        self.checks.iter().any(|check| check.status == CheckStatus::Warning)
    }

    /// The time the certificates are validated at: the time-stamp, else the claimed time, else `now`.
    pub fn validation_time(&self, now: OffsetDateTime) -> OffsetDateTime {
        match self.time_stamp_time.or(self.claimed_signing_time) {
            Some(time) => time,
            None => now,
        }
    }

    /// Records a check that passed.
    pub fn pass(&mut self, name: &str, details: &str) {
        self.add_check(name, CheckStatus::Passed, details);
    }

    /// Records a check that ended with a warning.
    pub fn warn(&mut self, name: &str, details: &str) {
        self.add_check(name, CheckStatus::Warning, details);
    }

    /// Records a check that failed.
    pub fn fail(&mut self, name: &str, details: &str) {
        self.add_check(name, CheckStatus::Failed, details);
    }

    /// Records a check that passed or failed by `is_passed`.
    pub fn check(&mut self, name: &str, is_passed: bool, details: &str) {
        let status = if is_passed {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        };
        self.add_check(name, status, details);
    }

    /// Records a check with its status.
    pub fn add_check(&mut self, name: &str, status: CheckStatus, details: &str) {
        self.checks.push(VerificationCheck {
            name: name.to_owned(),
            status,
            details: details.to_owned(),
        });
    }
}
