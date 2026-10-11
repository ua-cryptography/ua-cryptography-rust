/// The outcome of one verification step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckStatus {
    /// The step holds.
    Passed,
    /// Something could not be established (no trust anchor, no revocation data); the signature itself holds.
    Warning,
    /// The step fails: the signature is not valid.
    Failed,
}
