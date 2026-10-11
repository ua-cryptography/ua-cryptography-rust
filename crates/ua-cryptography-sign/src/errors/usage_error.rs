use std::fmt;

/// Why a command line is refused: reported with the command's help and exit code 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// An argument that is not an option.
    UnexpectedArgument {
        /// The argument.
        argument: String,
    },
    /// A flag given a value (`--force=yes`).
    FlagWithValue {
        /// The flag's name.
        name: String,
    },
    /// An option without its value.
    MissingValue {
        /// The option's name.
        name: String,
    },
    /// An option the command does not declare.
    UnknownOption {
        /// The option's name.
        name: String,
    },
    /// A single-valued option given twice.
    RepeatedOption {
        /// The option's name.
        name: String,
    },
    /// A required option is missing.
    MissingOption {
        /// The option's name.
        name: String,
    },
    /// A number option that is not a positive number.
    NotPositiveNumber {
        /// The option's name.
        name: String,
    },
    /// A curve degree that table Г.1 does not have.
    UnknownCurve {
        /// The degree given.
        m: u32,
        /// The degrees of table Г.1.
        known: Vec<u32>,
    },
    /// `--password-env` names a variable that is not set.
    PasswordVariableNotSet {
        /// The variable's name.
        variable: String,
    },
    /// `--password-file` names an empty file.
    EmptyPasswordFile {
        /// The file's path.
        path: String,
    },
    /// No password option and nothing to read from the redirected input.
    NoPassword,
    /// The password typed twice differs.
    PasswordMismatch,
    /// A new key store needs a password.
    EmptyPassword,
    /// The output file exists and `--force` is not given.
    FileExists {
        /// The file's path.
        path: String,
    },
    /// `info` without `--keystore` and `--cert`.
    NothingToShow,
    /// A signature format other than cades, xades, asic-s and asic-e.
    UnknownFormat {
        /// The format given (lowercased).
        format: String,
    },
    /// Several inputs to a format that signs one file.
    SeveralInputs {
        /// The format.
        format: String,
    },
    /// `--detached` with a format other than cades.
    DetachedNotCades,
    /// `--content-timestamp` with a format other than cades and asic-s.
    ContentTimeStampFormat,
    /// A level other than B, T and LT.
    UnknownLevel {
        /// The level given (uppercased).
        level: String,
    },
    /// Level T or LT (or a content time-stamp) without a time-stamping service.
    NoTimeStampService,
    /// Two inputs with the same file name.
    DuplicateInputName,
    /// A report format other than text and ini.
    UnknownReportFormat,
}

impl fmt::Display for UsageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedArgument { argument } => write!(formatter, "Unexpected argument '{argument}'."),
            Self::FlagWithValue { name } => write!(formatter, "--{name} takes no value."),
            Self::MissingValue { name } => write!(formatter, "--{name} needs a value."),
            Self::UnknownOption { name } => write!(formatter, "Unknown option --{name}."),
            Self::RepeatedOption { name } => write!(formatter, "--{name} is given more than once."),
            Self::MissingOption { name } => write!(formatter, "--{name} is required."),
            Self::NotPositiveNumber { name } => write!(formatter, "--{name} must be a positive number."),
            Self::UnknownCurve { m, known } => {
                let degrees: Vec<String> = known.iter().map(u32::to_string).collect();
                write!(formatter, "--curve {m}: table Г.1 has curves {}.", degrees.join(" "))
            }
            Self::PasswordVariableNotSet { variable } => {
                write!(formatter, "The environment variable {variable} is not set.")
            }
            Self::EmptyPasswordFile { path } => write!(formatter, "The password file {path} is empty."),
            Self::NoPassword => write!(
                formatter,
                "No password: use --password-env, --password-file or type it."
            ),
            Self::PasswordMismatch => write!(formatter, "The passwords do not match."),
            Self::EmptyPassword => write!(formatter, "The password must not be empty."),
            Self::FileExists { path } => write!(formatter, "{path} exists; add --force to overwrite it."),
            Self::NothingToShow => write!(formatter, "Give --keystore or --cert."),
            Self::UnknownFormat { format } => {
                write!(formatter, "--format {format}: expected cades, xades, asic-s or asic-e.")
            }
            Self::SeveralInputs { format } => {
                write!(formatter, "{format} signs one file; use xades or asic-e for several.")
            }
            Self::DetachedNotCades => write!(
                formatter,
                "--detached applies to cades only (asic-s and xades are always detached)."
            ),
            Self::ContentTimeStampFormat => write!(formatter, "--content-timestamp applies to cades and asic-s."),
            Self::UnknownLevel { level } => write!(formatter, "--level {level}: expected B, T or LT."),
            Self::NoTimeStampService => write!(
                formatter,
                "This level needs a time-stamping service: give --tsa URL (the certificate names none)."
            ),
            Self::DuplicateInputName => write!(formatter, "Two inputs have the same file name."),
            Self::UnknownReportFormat => write!(formatter, "--format must be text or ini."),
        }
    }
}

impl std::error::Error for UsageError {}
