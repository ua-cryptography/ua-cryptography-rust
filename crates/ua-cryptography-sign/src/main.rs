//! `ua-sign`: the command-line tool over `ua-cryptography-pki` — keygen, info, sign, verify. Everything is in the
//! library's [`ua_cryptography_sign::run`]; this file hands it the arguments, the standard streams and the environment.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(argument) => args.push(argument),
            Err(argument) => {
                eprintln!(
                    "error: the argument {} is not valid Unicode.",
                    argument.to_string_lossy()
                );
                return ExitCode::from(ua_cryptography_sign::EXIT_ERROR);
            }
        }
    }
    let environment = |name: &str| std::env::var(name).ok();
    let code = ua_cryptography_sign::run(
        &args,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
        &environment,
    );
    ExitCode::from(code)
}
