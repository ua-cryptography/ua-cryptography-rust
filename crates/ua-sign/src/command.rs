use std::io::Write;

use crate::arguments::Arguments;
use crate::commands::{info, keygen, sign, verify};
use crate::errors::CommandFailure;

/// What a command does with its parsed options, the output and the environment; returns the exit code.
pub type CommandAction = fn(&Arguments, &mut dyn Write, &dyn Fn(&str) -> Option<String>) -> Result<u8, CommandFailure>;

/// A command of `ua-sign`: its name, help, the options it declares and what it does.
pub struct Command {
    /// The name on the command line.
    pub name: &'static str,
    /// The help printed by `--help` and after a usage error.
    pub help: &'static str,
    /// The options taking a value.
    pub options: &'static [&'static str],
    /// The flags.
    pub flags: &'static [&'static str],
    /// What the command does.
    pub action: CommandAction,
}

/// Every command.
const COMMANDS: [Command; 4] = [
    Command {
        name: "keygen",
        help: keygen::HELP,
        options: &keygen::OPTIONS,
        flags: &keygen::FLAGS,
        action: keygen::create_key_store,
    },
    Command {
        name: "info",
        help: info::HELP,
        options: &info::OPTIONS,
        flags: &info::FLAGS,
        action: info::show,
    },
    Command {
        name: "sign",
        help: sign::HELP,
        options: &sign::OPTIONS,
        flags: &sign::FLAGS,
        action: sign::sign_files,
    },
    Command {
        name: "verify",
        help: verify::HELP,
        options: &verify::OPTIONS,
        flags: &verify::FLAGS,
        action: verify::verify_signature,
    },
];

/// The command named `name`, if there is one.
pub fn find_command(name: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|command| command.name == name)
}
