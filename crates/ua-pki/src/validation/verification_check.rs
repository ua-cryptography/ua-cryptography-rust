use crate::validation::CheckStatus;

/// One verification step and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCheck {
    /// What was checked, e.g. "CMS: signature" or "signer: trust".
    pub name: String,
    /// The outcome.
    pub status: CheckStatus,
    /// What was found.
    pub details: String,
}
