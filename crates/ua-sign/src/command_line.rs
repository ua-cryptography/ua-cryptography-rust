use std::io::Write;

use crate::arguments::Arguments;
use crate::command::{Command, find_command};
use crate::errors::CommandFailure;
use crate::{EXIT_ERROR, EXIT_VALID};

/// The overview printed without a command.
const USAGE: &str =
    "ua-sign — DSTU 4145 signatures of the Ukrainian PKI (CAdES, XAdES, ASiC-S, ASiC-E) with keys in JKS.

Commands:
  keygen   create a key store with a new DSTU 4145 key and a self-signed certificate
  info     show the entries of a key store or the contents of certificates
  sign     sign files
  verify   verify a signature and show every check

Run 'ua-sign <command> --help' for the options of a command.
Exit codes: 0 done / valid, 1 invalid signature, 2 error.";

/// What asks for the overview.
const OVERVIEW_REQUESTS: [&str; 3] = ["--help", "-h", "help"];
/// What asks for a command's help.
const HELP_REQUESTS: [&str; 2] = ["--help", "-h"];

// A failed write to the output or error stream has nowhere to be reported: the exit code still tells the outcome.

/// Runs `ua-sign` with `args` (without the program name): the command's report goes to `output`, errors to `error`;
/// `environment` looks up environment variables (`--password-env`). Returns the exit code: [`EXIT_VALID`](crate::EXIT_VALID)
/// when done or the signature is valid, [`EXIT_INVALID`](crate::EXIT_INVALID) when it is not,
/// [`EXIT_ERROR`](crate::EXIT_ERROR) on a usage or processing error.
pub fn run(
    args: &[String],
    output: &mut dyn Write,
    error: &mut dyn Write,
    environment: &dyn Fn(&str) -> Option<String>,
) -> u8 {
    let Some(first) = args.first() else {
        let _ = writeln!(output, "{USAGE}");
        return EXIT_ERROR;
    };
    if OVERVIEW_REQUESTS.contains(&first.as_str()) {
        let _ = writeln!(output, "{USAGE}");
        return EXIT_VALID;
    }
    let Some(command) = find_command(first) else {
        let _ = writeln!(error, "Unknown command '{first}'.");
        let _ = writeln!(error, "{USAGE}");
        return EXIT_ERROR;
    };
    let options = &args[1..];
    if options.iter().any(|option| HELP_REQUESTS.contains(&option.as_str())) {
        let _ = writeln!(output, "{}", command.help);
        return EXIT_VALID;
    }
    match run_command(command, options, output, environment) {
        Ok(code) => code,
        Err(failure) => {
            report_failure(command, &failure, error);
            EXIT_ERROR
        }
    }
}

fn run_command(
    command: &Command,
    options: &[String],
    output: &mut dyn Write,
    environment: &dyn Fn(&str) -> Option<String>,
) -> Result<u8, CommandFailure> {
    let arguments = Arguments::parse(options, command.options, command.flags)?;
    let code = (command.action)(&arguments, output, environment)?;
    output.flush()?;
    Ok(code)
}

// A usage error is followed by the command's help.
fn report_failure(command: &Command, failure: &CommandFailure, error: &mut dyn Write) {
    let _ = writeln!(error, "error: {failure}");
    if let CommandFailure::Usage(_) = failure {
        let _ = writeln!(error);
        let _ = writeln!(error, "{}", command.help);
    }
}
