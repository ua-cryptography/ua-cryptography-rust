//! `ua-sign`: DSTU 4145 keys in JKS key stores, signing and verification in CAdES, XAdES, ASiC-S and ASiC-E at levels
//! B, T and LT, built on `ua-cryptography-pki`. The binary (`main.rs`) only hands the process's arguments, streams and
//! environment to [`run`], which the tests call in process.
//!
//! - [`run`]: parses a command line, runs `keygen`, `info`, `sign` or `verify`, returns the exit code.
//! - Exit codes: [`EXIT_VALID`] (done / valid), [`EXIT_INVALID`] (the signature is invalid), [`EXIT_ERROR`] (a usage
//!   or processing error).
//! - Inside: `arguments` (the options of a command), `passwords` (option, environment, file or terminal), `report`
//!   (text and INI), `commands/*` (one file per command), `files` (paths and file access).

#![forbid(unsafe_code)]

mod arguments;
mod command;
mod command_line;
mod commands;
mod errors;
mod files;
mod passwords;
mod report;

pub use command_line::run;

/// The exit code of a command done or a valid signature.
pub const EXIT_VALID: u8 = 0;
/// The exit code of an invalid signature.
pub const EXIT_INVALID: u8 = 1;
/// The exit code of a usage or processing error.
pub const EXIT_ERROR: u8 = 2;
