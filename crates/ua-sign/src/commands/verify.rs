//! `verify`: a signature of any format (recognised by the content), every check printed as text or as an INI report;
//! the data of a detached signature is `--data` or the file next to it by the name the signature uses.

use std::cell::RefCell;
use std::io::Write;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;
use ua_pki::{
    Certificate, CheckStatus, HttpCertificateSource, HttpOcspService, ValidationOptions, VerificationResult,
    certificate_files, signature_verifier,
};

use crate::arguments::Arguments;
use crate::errors::{CommandFailure, UsageError};
use crate::files::{create_directory, file_name, file_stem, full_path, is_inside, read_file, write_file};
use crate::{EXIT_INVALID, EXIT_VALID, report};

/// The command's help.
pub const HELP: &str = "ua-sign verify --in SIGNATURE [options]

  --in FILE                 .p7s, .xml, .asics or .asice (the format is recognised by the content)
  --data FILE               the signed file of a detached signature; repeatable for XAdES
                            (default: next to the signature, by the name the signature uses)
  --trust FILE              trusted root certificates (DER, PEM bundle, .p7b); repeatable
  --certs FILE              more certificates to complete chains; repeatable
  --online                  ask OCSP responders and download missing CA certificates
  --extract DIR             write the signed content into this directory
  --quiet                   print only the summary
  --format text|ini         text (default) or an INI report with every detail: algorithms, signer,
                            digests, time-stamps, certificate paths, OCSP statuses and checks
  --report FILE             also write the INI report to FILE (UTF-8)";

/// The options taking a value.
pub const OPTIONS: [&str; 7] = [IN, DATA, TRUST, CERTS, EXTRACT, FORMAT, REPORT];

/// The flags.
pub const FLAGS: [&str; 2] = [ONLINE, QUIET];

const IN: &str = "in";
const DATA: &str = "data";
const TRUST: &str = "trust";
const CERTS: &str = "certs";
const EXTRACT: &str = "extract";
const FORMAT: &str = "format";
const REPORT: &str = "report";
const ONLINE: &str = "online";
const QUIET: &str = "quiet";
/// The extension of a detached CAdES whose data lies next to it under the name without it.
const P7S_EXTENSION: &str = "p7s";
/// The name the verifier gives the encapsulated content of a CAdES signature.
const ENCAPSULATED_CONTENT: &str = "content";
/// What a check that misses a certificate says.
const MISSING_CERTIFICATE_DETAILS: &str = "is not available";

/// Verifies the signature the options name, prints the report and extracts the signed files.
pub fn verify_signature(
    arguments: &Arguments,
    output: &mut dyn Write,
    _environment: &dyn Fn(&str) -> Option<String>,
) -> Result<u8, CommandFailure> {
    let path = arguments.get(IN)?;
    let is_ini = match arguments.find(FORMAT)? {
        None | Some("text") => false,
        Some("ini") => true,
        Some(_) => return Err(UsageError::UnknownReportFormat.into()),
    };
    let signature = read_file(path)?;
    let data = DetachedData::read(path, arguments.select(DATA))?;
    let is_online = arguments.has_flag(ONLINE);
    let ocsp = HttpOcspService::new(None);
    let downloads = HttpCertificateSource::new();
    let options = ValidationOptions {
        trust_anchors: load_certificates(arguments.select(TRUST))?,
        extra_certificates: load_certificates(arguments.select(CERTS))?,
        online_ocsp: is_online.then_some(&ocsp as _),
        downloads: is_online.then_some(&downloads as _),
        current_time: None,
    };
    let result = signature_verifier::verify(&signature, &|name| data.find(name), &options)?;
    data.check_read()?;

    let verified_at = OffsetDateTime::now_utc();
    if is_ini {
        report::write_ini(path, &result, output, verified_at)?;
    } else {
        report::write_text(path, &result, output, arguments.has_flag(QUIET))?;
        if !is_online && misses_certificates(&result) {
            writeln!(
                output,
                "Hint: certificates are missing; --online downloads them from the certificates' caIssuers addresses, \
                 or give them with --certs."
            )?;
        }
    }
    if let Some(report_path) = arguments.find(REPORT)? {
        let mut ini = Vec::new();
        report::write_ini(path, &result, &mut ini, verified_at)?;
        write_file(report_path, &ini)?;
        if !is_ini {
            writeln!(output, "Report: {report_path}")?;
        }
    }
    if let Some(directory) = arguments.find(EXTRACT)? {
        extract(path, &result, directory, output, is_ini)?;
    }
    Ok(if result.is_valid() { EXIT_VALID } else { EXIT_INVALID })
}

/// The data of detached signatures: the `--data` files by name, else the files next to the signature.
struct DetachedData {
    signature_path: PathBuf,
    directory: PathBuf,
    given: Vec<(String, Vec<u8>)>,
    // A file found but unreadable: reported after the verification, which cannot be interrupted.
    read_failure: RefCell<Option<CommandFailure>>,
}

impl DetachedData {
    fn read(signature_path: &str, data_paths: &[String]) -> Result<Self, CommandFailure> {
        let full = full_path(signature_path)?;
        let directory = match full.parent() {
            Some(parent) => parent.to_path_buf(),
            None => full.clone(),
        };
        let mut given: Vec<(String, Vec<u8>)> = Vec::new();
        for data_path in data_paths {
            let name = file_name(data_path);
            if given.iter().any(|(known, _)| *known == name) {
                return Err(CommandFailure::DuplicateDataName { name });
            }
            given.push((name, read_file(data_path)?));
        }
        Ok(Self {
            signature_path: full,
            directory,
            given,
            read_failure: RefCell::new(None),
        })
    }

    // `name` is a XAdES reference; none is a detached CAdES.
    fn find(&self, name: Option<&str>) -> Option<Vec<u8>> {
        match name {
            None => self.find_single().or_else(|| self.find_next_to_cades()),
            Some(name) => self
                .find_given(name)
                .or_else(|| self.find_single())
                .or_else(|| self.find_below_directory(name)),
        }
    }

    // One --data file stands for whatever the signature asks.
    fn find_single(&self) -> Option<Vec<u8>> {
        match self.given.as_slice() {
            [(_, content)] => Some(content.clone()),
            _ => None,
        }
    }

    fn find_given(&self, name: &str) -> Option<Vec<u8>> {
        let base_name = file_name(name);
        self.given
            .iter()
            .find(|(known, _)| *known == base_name)
            .map(|(_, content)| content.clone())
    }

    // Only files below the signature's directory: a reference like "../../secret" is not followed.
    fn find_below_directory(&self, name: &str) -> Option<Vec<u8>> {
        let candidate = full_path(self.directory.join(name)).ok()?;
        if !is_inside(&candidate, &self.directory) {
            return None;
        }
        self.read_existing(&candidate)
    }

    // doc.txt for doc.txt.p7s.
    fn find_next_to_cades(&self) -> Option<Vec<u8>> {
        let is_p7s = self
            .signature_path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case(P7S_EXTENSION));
        if !is_p7s {
            return None;
        }
        self.read_existing(&self.signature_path.with_extension(""))
    }

    fn read_existing(&self, path: &Path) -> Option<Vec<u8>> {
        if !path.is_file() {
            return None;
        }
        match read_file(path) {
            Ok(content) => Some(content),
            Err(failure) => {
                self.read_failure.borrow_mut().get_or_insert(failure);
                None
            }
        }
    }

    fn check_read(&self) -> Result<(), CommandFailure> {
        match self.read_failure.borrow_mut().take() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

fn load_certificates(paths: &[String]) -> Result<Vec<Certificate>, CommandFailure> {
    let mut certificates = Vec::new();
    for path in paths {
        certificates.extend(certificate_files::load(Path::new(path))?);
    }
    Ok(certificates)
}

fn misses_certificates(result: &VerificationResult) -> bool {
    result
        .signatures
        .iter()
        .flat_map(|report| &report.checks)
        .any(|check| check.status != CheckStatus::Passed && check.details.contains(MISSING_CERTIFICATE_DETAILS))
}

// Every signed file into `directory`; the encapsulated content under the signature's name without its extension.
fn extract(
    signature_path: &str,
    result: &VerificationResult,
    directory: &str,
    output: &mut dyn Write,
    is_ini: bool,
) -> Result<(), CommandFailure> {
    create_directory(Path::new(directory))?;
    let root = full_path(directory)?;
    for file in &result.signed_files {
        let name = if file.name == ENCAPSULATED_CONTENT {
            file_stem(signature_path)
        } else {
            file.name.clone()
        };
        let target = full_path(root.join(&name))?;
        if !is_inside(&target, &root) {
            return Err(CommandFailure::ExtractionOutside {
                name: file.name.clone(),
                directory: directory.to_owned(),
            });
        }
        if let Some(parent) = target.parent() {
            create_directory(parent)?;
        }
        write_file(&target, &file.content)?;
        if is_ini {
            writeln!(output, "; extracted: {}", target.display())?;
        } else {
            writeln!(output, "Extracted: {}", target.display())?;
        }
    }
    Ok(())
}
