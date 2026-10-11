use serde::Serialize;

/// The outcome of one verification step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    /// The step holds.
    Passed,
    /// Something could not be established; the signature itself holds.
    Warning,
    /// The step fails: the signature is not valid.
    Failed,
}
