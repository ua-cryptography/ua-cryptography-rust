use serde::Serialize;

use crate::models::reports::CheckOutcome;

/// One verification step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckRow {
    /// What was checked.
    pub name: String,
    /// How it ended.
    pub status: CheckOutcome,
    /// What was found.
    pub details: String,
}
