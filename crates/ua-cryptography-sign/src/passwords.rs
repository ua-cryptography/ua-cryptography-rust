//! The key store password: `--password` (visible in the process list, for tests and scripts on a private machine),
//! `--password-env NAME`, `--password-file PATH` (first line), or typed at the terminal without echo.

use std::io::{BufRead, IsTerminal, Write};

use crate::arguments::Arguments;
use crate::errors::{CommandFailure, UsageError};
use crate::files::read_file;

/// The help lines of the password options, for the help of every command that opens a key store.
macro_rules! password_help {
    () => {
        "  --password VALUE          the key store password (visible to other processes; prefer the next two)
  --password-env NAME       read the password from an environment variable
  --password-file PATH      read the password from the first line of a file
                            (without these options the password is asked at the terminal)"
    };
}
pub(crate) use password_help;

/// The option with the password itself.
pub const PASSWORD: &str = "password";
/// The option naming the environment variable that holds the password.
pub const PASSWORD_ENV: &str = "password-env";
/// The option naming the file whose first line is the password.
pub const PASSWORD_FILE: &str = "password-file";
/// A UTF-8 byte order mark a text editor may put before the password.
const BYTE_ORDER_MARK: char = '\u{feff}';
/// The prompt at the terminal.
const PROMPT: &str = "Key store password: ";
/// The prompt that confirms a new password.
const REPEAT_PROMPT: &str = "Repeat the password: ";

/// Reads the password from the options, the environment, a file or the terminal; `is_confirmed` asks for it twice at
/// the terminal (a new key store).
pub fn read_password(
    arguments: &Arguments,
    environment: &dyn Fn(&str) -> Option<String>,
    is_confirmed: bool,
) -> Result<String, CommandFailure> {
    if let Some(literal) = arguments.find(PASSWORD)? {
        return Ok(literal.to_owned());
    }
    if let Some(variable) = arguments.find(PASSWORD_ENV)? {
        return environment(variable).ok_or_else(|| {
            UsageError::PasswordVariableNotSet {
                variable: variable.to_owned(),
            }
            .into()
        });
    }
    if let Some(path) = arguments.find(PASSWORD_FILE)? {
        return read_first_line(path);
    }
    if !std::io::stdin().is_terminal() {
        return read_redirected_input();
    }
    let password = prompt(PROMPT)?;
    if is_confirmed && prompt(REPEAT_PROMPT)? != password {
        return Err(UsageError::PasswordMismatch.into());
    }
    Ok(password)
}

fn read_first_line(path: &str) -> Result<String, CommandFailure> {
    let content = read_file(path)?;
    let text = String::from_utf8_lossy(&content);
    let text = match text.strip_prefix(BYTE_ORDER_MARK) {
        Some(rest) => rest,
        None => &text,
    };
    if text.is_empty() {
        return Err(UsageError::EmptyPasswordFile { path: path.to_owned() }.into());
    }
    Ok(first_line(text).to_owned())
}

fn read_redirected_input() -> Result<String, CommandFailure> {
    let mut line = String::new();
    let read = std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(password_input_failure)?;
    if read == 0 {
        return Err(UsageError::NoPassword.into());
    }
    Ok(first_line(&line).to_owned())
}

// Typed without echo; the prompt goes to the standard error, as the password is not part of the output.
fn prompt(text: &str) -> Result<String, CommandFailure> {
    let mut error = std::io::stderr();
    error.write_all(text.as_bytes())?;
    error.flush()?;
    rpassword::read_password().map_err(password_input_failure)
}

fn password_input_failure(error: std::io::Error) -> CommandFailure {
    CommandFailure::PasswordInput {
        reason: error.to_string(),
    }
}

// A line ends at "\n", "\r\n" or "\r".
fn first_line(text: &str) -> &str {
    match text.find(['\r', '\n']) {
        Some(end) => &text[..end],
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_line_ends_at_any_line_break() {
        assert_eq!(first_line("secret\r\nmore"), "secret");
        assert_eq!(first_line("secret\n"), "secret");
        assert_eq!(first_line("secret"), "secret");
        assert_eq!(first_line("\n"), "");
    }
}
