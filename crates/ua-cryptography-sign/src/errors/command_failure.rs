use std::fmt;

use ua_cryptography_pki::{
    AlgorithmError, CertificateError, ContainerError, DistinguishedNameError, KeyError, KeyStoreError, SigningError,
    VerificationError,
};

use crate::errors::UsageError;

/// Why one command did not finish: a usage error (shown with the command's help) or a processing error (a wrong
/// password, an unreadable file, a network failure). Either way the exit code is 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandFailure {
    /// The command line is refused.
    Usage(UsageError),
    /// A file (or a directory on its path) does not exist.
    FileNotFound {
        /// The file's full path.
        path: String,
    },
    /// The file may not be read or written.
    FileAccessDenied {
        /// The file's full path.
        path: String,
    },
    /// A file cannot be read or written for another reason.
    File {
        /// The file's path as given.
        path: String,
        /// The operating system's reason.
        reason: String,
    },
    /// The password cannot be read from the terminal or the standard input.
    PasswordInput {
        /// The operating system's reason.
        reason: String,
    },
    /// The output cannot be written.
    Output {
        /// The operating system's reason.
        reason: String,
    },
    /// Two `--data` files have the same name.
    DuplicateDataName {
        /// The file name.
        name: String,
    },
    /// A signed file's name leads outside the extraction directory.
    ExtractionOutside {
        /// The signed file's name.
        name: String,
        /// The extraction directory as given.
        directory: String,
    },
    /// The key store is refused (a wrong password among others).
    KeyStore(KeyStoreError),
    /// A certificate file is refused.
    Certificate(CertificateError),
    /// The subject of a new certificate is refused.
    DistinguishedName(DistinguishedNameError),
    /// A hash name is refused.
    Algorithm(AlgorithmError),
    /// A key cannot be read or written.
    Key(KeyError),
    /// Signing failed (a time-stamping or OCSP service among others).
    Signing(SigningError),
    /// An ASiC container cannot be written.
    Container(ContainerError),
    /// The signed file cannot be read as any format.
    Verification(VerificationError),
}

impl fmt::Display for CommandFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(error) => write!(formatter, "{error}"),
            Self::FileNotFound { path } => write!(formatter, "Could not find file '{path}'."),
            Self::FileAccessDenied { path } => write!(formatter, "Access to the path '{path}' is denied."),
            Self::File { path, reason } => write!(formatter, "{path}: {reason}."),
            Self::PasswordInput { reason } => write!(formatter, "Cannot read the password: {reason}."),
            Self::Output { reason } => write!(formatter, "Cannot write the output: {reason}."),
            Self::DuplicateDataName { name } => write!(formatter, "Two --data files are named '{name}'."),
            Self::ExtractionOutside { name, directory } => {
                write!(formatter, "Refusing to extract '{name}' outside {directory}.")
            }
            Self::KeyStore(error) => write!(formatter, "{error}"),
            Self::Certificate(error) => write!(formatter, "{error}"),
            Self::DistinguishedName(error) => write!(formatter, "{error}"),
            Self::Algorithm(error) => write!(formatter, "{error}"),
            Self::Key(error) => write!(formatter, "{error}"),
            Self::Signing(error) => write!(formatter, "{error}"),
            Self::Container(error) => write!(formatter, "{error}"),
            Self::Verification(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CommandFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Usage(error) => Some(error),
            Self::KeyStore(error) => Some(error),
            Self::Certificate(error) => Some(error),
            Self::DistinguishedName(error) => Some(error),
            Self::Algorithm(error) => Some(error),
            Self::Key(error) => Some(error),
            Self::Signing(error) => Some(error),
            Self::Container(error) => Some(error),
            Self::Verification(error) => Some(error),
            _ => None,
        }
    }
}

impl From<UsageError> for CommandFailure {
    fn from(error: UsageError) -> Self {
        Self::Usage(error)
    }
}

impl From<KeyStoreError> for CommandFailure {
    fn from(error: KeyStoreError) -> Self {
        Self::KeyStore(error)
    }
}

impl From<CertificateError> for CommandFailure {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

impl From<DistinguishedNameError> for CommandFailure {
    fn from(error: DistinguishedNameError) -> Self {
        Self::DistinguishedName(error)
    }
}

impl From<AlgorithmError> for CommandFailure {
    fn from(error: AlgorithmError) -> Self {
        Self::Algorithm(error)
    }
}

impl From<KeyError> for CommandFailure {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<SigningError> for CommandFailure {
    fn from(error: SigningError) -> Self {
        Self::Signing(error)
    }
}

impl From<ContainerError> for CommandFailure {
    fn from(error: ContainerError) -> Self {
        Self::Container(error)
    }
}

impl From<VerificationError> for CommandFailure {
    fn from(error: VerificationError) -> Self {
        Self::Verification(error)
    }
}

impl From<std::io::Error> for CommandFailure {
    fn from(error: std::io::Error) -> Self {
        Self::Output {
            reason: error.to_string(),
        }
    }
}
