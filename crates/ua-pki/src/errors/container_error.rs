use std::fmt;

/// Why an ASiC container (a ZIP archive) cannot be written or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    /// An entry name would escape the container or replace the mimetype entry.
    InvalidEntryName {
        /// The name given.
        name: String,
    },
    /// The ZIP archive is malformed or cannot be written.
    Zip {
        /// What the ZIP library reported.
        message: String,
    },
    /// The entries are larger than 2 GiB when unpacked.
    TooLarge,
}

impl fmt::Display for ContainerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEntryName { name } => write!(formatter, "Invalid entry name '{name}'."),
            Self::Zip { message } => write!(formatter, "Invalid ZIP container: {message}."),
            Self::TooLarge => write!(formatter, "The container is too large when unpacked."),
        }
    }
}

impl std::error::Error for ContainerError {}
