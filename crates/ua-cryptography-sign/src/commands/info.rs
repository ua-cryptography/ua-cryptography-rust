//! `info`: the entries of a key store, or the certificates of files (DER, PEM, `.p7b`).

use std::io::Write;
use std::path::Path;

use ua_cryptography_pki::{JksEntry, JksKeyStore, certificate_files};

use crate::arguments::Arguments;
use crate::errors::{CommandFailure, UsageError};
use crate::files::read_file;
use crate::passwords::{self, password_help};
use crate::{EXIT_VALID, report};

/// The command's help.
pub const HELP: &str = concat!(
    "ua-sign info (--keystore PATH | --cert PATH...)

  --keystore PATH           list the entries of a JKS key store (asks for the password)
  --cert PATH               show a certificate (DER, PEM or a .p7b bundle); repeatable
",
    password_help!()
);

/// The options taking a value.
pub const OPTIONS: [&str; 5] = [
    KEYSTORE,
    CERT,
    passwords::PASSWORD,
    passwords::PASSWORD_ENV,
    passwords::PASSWORD_FILE,
];

/// The flags.
pub const FLAGS: [&str; 0] = [];

const KEYSTORE: &str = "keystore";
const CERT: &str = "cert";
/// The indent of a certificate's lines under its entry or file.
const INDENT: &str = "  ";

/// Lists the key store's entries and describes the certificates of the files given.
pub fn show(
    arguments: &Arguments,
    output: &mut dyn Write,
    environment: &dyn Fn(&str) -> Option<String>,
) -> Result<u8, CommandFailure> {
    let keystore = arguments.find(KEYSTORE)?;
    let certificate_paths = arguments.select(CERT);
    if keystore.is_none() && certificate_paths.is_empty() {
        return Err(UsageError::NothingToShow.into());
    }
    if let Some(keystore) = keystore {
        let data = read_file(keystore)?;
        let store = JksKeyStore::load(&data, &passwords::read_password(arguments, environment, false)?)?;
        list_entries(keystore, &store, output)?;
    }
    for path in certificate_paths {
        for certificate in certificate_files::load(Path::new(path))? {
            writeln!(output, "{path}:")?;
            report::describe_certificate(&certificate, output, INDENT)?;
            if certificate.is_self_issued() {
                let verdict = if certificate.is_signed_by(&certificate) {
                    "valid"
                } else {
                    "INVALID"
                };
                writeln!(output, "{INDENT}Self-signature: {verdict}")?;
            }
        }
    }
    Ok(EXIT_VALID)
}

fn list_entries(keystore: &str, store: &JksKeyStore, output: &mut dyn Write) -> Result<(), CommandFailure> {
    writeln!(output, "Key store {keystore}: {} entries", store.entries().len())?;
    for entry in store.entries() {
        writeln!(output)?;
        let created = report::format_date(entry.created());
        match entry {
            JksEntry::PrivateKey(key) => {
                writeln!(
                    output,
                    "[{}] private key, created {created}, chain of {}",
                    key.alias,
                    key.chain.len()
                )?;
                for certificate in &key.chain {
                    report::describe_certificate(certificate, output, INDENT)?;
                }
            }
            JksEntry::TrustedCertificate(trusted) => {
                writeln!(output, "[{}] trusted certificate", trusted.alias)?;
                report::describe_certificate(&trusted.certificate, output, INDENT)?;
            }
        }
    }
    Ok(())
}
