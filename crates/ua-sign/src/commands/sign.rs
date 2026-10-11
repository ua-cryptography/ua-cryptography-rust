//! `sign`: CAdES (.p7s, enveloped or detached), XAdES (.xml), ASiC-S (.asics) or ASiC-E (.asice) at levels B, T and LT,
//! with the key of a JKS key store and, for T and LT, the time-stamping and OCSP services over HTTP.

use std::io::Write;
use std::path::Path;

use ua_pki::{
    CadesOptions, CadesSigner, Certificate, HttpCertificateSource, HttpOcspService, HttpTimeStampService, JksKeyStore,
    SignatureLevel, SignatureServices, SignedFile, SigningKey, XadesSigner, algorithms, asic_container,
    certificate_files,
};

use crate::EXIT_VALID;
use crate::arguments::Arguments;
use crate::errors::{CommandFailure, UsageError};
use crate::files::{check_writable, file_name, read_file, write_file};
use crate::passwords::{self, password_help};

/// The command's help.
pub const HELP: &str = concat!(
    "ua-sign sign --keystore PATH --format FORMAT --in FILE [options]

  --keystore PATH           JKS key store with the signing key
  --alias NAME              the key to use when the store holds several
  --format FORMAT           cades   CMS signature (.p7s), enveloped or with --detached
                            xades   detached XML signature (.xml) next to the files
                            asic-s  ZIP container with the file and a detached CAdES (.asics)
                            asic-e  ZIP container with the files and a XAdES signature (.asice)
  --in FILE                 the file to sign; repeatable for xades and asic-e
  --out FILE                the result (default: the input name plus the format's extension)
  --level LEVEL             B (default), T (+ time-stamp) or LT (+ certificates and OCSP:
                            XAdES-B-LT, CAdES-X Long)
  --hash NAME               dstu7564 (default, DSTU 7564-256) or gost34311
  --detached                cades: do not include the data in the signature
  --content-timestamp       cades: also time-stamp the data itself (needs a time-stamping service)
  --tsa URL                 time-stamping service (default: the one named in the signer's certificate)
  --ocsp URL                OCSP responder for every certificate (default: from each certificate)
  --certs FILE              CA certificates to complete the signer's chain; repeatable
  --force                   overwrite an existing output file
",
    password_help!()
);

/// The options taking a value.
pub const OPTIONS: [&str; 13] = [
    KEYSTORE,
    ALIAS,
    FORMAT,
    IN,
    OUT,
    LEVEL,
    HASH,
    TSA,
    OCSP,
    CERTS,
    passwords::PASSWORD,
    passwords::PASSWORD_ENV,
    passwords::PASSWORD_FILE,
];

/// The flags.
pub const FLAGS: [&str; 3] = [DETACHED, CONTENT_TIMESTAMP, FORCE];

const KEYSTORE: &str = "keystore";
const ALIAS: &str = "alias";
const FORMAT: &str = "format";
const IN: &str = "in";
const OUT: &str = "out";
const LEVEL: &str = "level";
const HASH: &str = "hash";
const TSA: &str = "tsa";
const OCSP: &str = "ocsp";
const CERTS: &str = "certs";
const DETACHED: &str = "detached";
const CONTENT_TIMESTAMP: &str = "content-timestamp";
const FORCE: &str = "force";
/// The level when none is given.
const DEFAULT_LEVEL: &str = "B";
/// The hash when none is given.
const DEFAULT_HASH: &str = "dstu7564";

/// The signature formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Cades,
    Xades,
    AsicS,
    AsicE,
}

impl Format {
    fn parse(name: &str) -> Result<Self, UsageError> {
        match name {
            "cades" => Ok(Self::Cades),
            "xades" => Ok(Self::Xades),
            "asic-s" => Ok(Self::AsicS),
            "asic-e" => Ok(Self::AsicE),
            _ => Err(UsageError::UnknownFormat {
                format: name.to_owned(),
            }),
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Cades => ".p7s",
            Self::Xades => ".xml",
            Self::AsicS => ".asics",
            Self::AsicE => ".asice",
        }
    }

    // CAdES inside: one file, detached or content time-stamped.
    fn is_cades(self) -> bool {
        matches!(self, Self::Cades | Self::AsicS)
    }
}

/// What `sign` makes, read from the options.
struct SignRequest<'a> {
    format_name: String,
    format: Format,
    inputs: &'a [String],
    level: SignatureLevel,
    hash_oid: String,
    out_path: String,
    is_detached: bool,
    has_content_time_stamp: bool,
}

/// Signs the files the options name and writes the signature.
pub fn sign_files(
    arguments: &Arguments,
    output: &mut dyn Write,
    environment: &dyn Fn(&str) -> Option<String>,
) -> Result<u8, CommandFailure> {
    let request = read_request(arguments)?;
    check_writable(&request.out_path, arguments.has_flag(FORCE))?;
    let files = read_inputs(request.inputs)?;

    let keystore = read_file(arguments.get(KEYSTORE)?)?;
    let password = passwords::read_password(arguments, environment, false)?;
    let store = JksKeyStore::load(&keystore, &password)?;
    let signer = SigningKey::from_jks(&store, &password, arguments.find(ALIAS)?, None)?;
    let extra = load_certificates(arguments.select(CERTS))?;

    let needs_time_stamps = request.level >= SignatureLevel::T || request.has_content_time_stamp;
    let tsa_url = match arguments.find(TSA)? {
        Some(url) => Some(url.to_owned()),
        None => signer.chain().iter().flat_map(Certificate::time_stamp_urls).next(),
    };
    if needs_time_stamps && tsa_url.is_none() {
        return Err(UsageError::NoTimeStampService.into());
    }
    let is_long_term = request.level >= SignatureLevel::LT;
    let ocsp_url = if is_long_term { arguments.find(OCSP)? } else { None };
    let clients = HttpClients::new(tsa_url.as_deref().filter(|_| needs_time_stamps), is_long_term, ocsp_url);
    let subject = signer.certificate().subject().to_string();
    let signature = create_signature(&request, &files, signer, clients.to_services(extra))?;
    write_file(&request.out_path, &signature)?;

    writeln!(output, "Signed:  {}", request.inputs.join(", "))?;
    writeln!(output, "Signer:  {subject}")?;
    let detached = if request.is_detached { ", detached" } else { "" };
    writeln!(
        output,
        "Format:  {}, {}, {}{detached}",
        request.format_name,
        level_name(request.format, request.level),
        algorithms::hash_name(&request.hash_oid)
    )?;
    if let (true, Some(url)) = (needs_time_stamps, &tsa_url) {
        writeln!(output, "TSA:     {url}")?;
    }
    writeln!(output, "Written: {}", request.out_path)?;
    Ok(EXIT_VALID)
}

/// The HTTP clients of the services a level needs.
struct HttpClients {
    time_stamps: Option<HttpTimeStampService>,
    ocsp: Option<HttpOcspService>,
    downloads: Option<HttpCertificateSource>,
}

impl HttpClients {
    // The time-stamping service at `tsa_url`; for long-term data the OCSP responders and caIssuers downloads.
    fn new(tsa_url: Option<&str>, is_long_term: bool, ocsp_url: Option<&str>) -> Self {
        Self {
            time_stamps: tsa_url.map(HttpTimeStampService::new),
            ocsp: is_long_term.then(|| HttpOcspService::new(ocsp_url)),
            downloads: is_long_term.then(HttpCertificateSource::new),
        }
    }

    fn to_services(&self, extra_certificates: Vec<Certificate>) -> SignatureServices<'_> {
        SignatureServices {
            time_stamps: self.time_stamps.as_ref().map(|client| client as _),
            ocsp: self.ocsp.as_ref().map(|client| client as _),
            downloads: self.downloads.as_ref().map(|client| client as _),
            extra_certificates,
        }
    }
}

fn read_request(arguments: &Arguments) -> Result<SignRequest<'_>, CommandFailure> {
    let format_name = arguments.get(FORMAT)?.to_lowercase();
    let format = Format::parse(&format_name)?;
    let inputs = arguments.select(IN);
    if inputs.is_empty() {
        return Err(UsageError::MissingOption { name: IN.to_owned() }.into());
    }
    if inputs.len() > 1 && format.is_cades() {
        return Err(UsageError::SeveralInputs { format: format_name }.into());
    }
    let is_detached = arguments.has_flag(DETACHED);
    if is_detached && format != Format::Cades {
        return Err(UsageError::DetachedNotCades.into());
    }
    let has_content_time_stamp = arguments.has_flag(CONTENT_TIMESTAMP);
    if has_content_time_stamp && !format.is_cades() {
        return Err(UsageError::ContentTimeStampFormat.into());
    }
    let level = match arguments.find(LEVEL)? {
        Some(level) => parse_level(level)?,
        None => parse_level(DEFAULT_LEVEL)?,
    };
    let hash_oid = match arguments.find(HASH)? {
        Some(name) => algorithms::parse_hash_name(name)?,
        None => algorithms::parse_hash_name(DEFAULT_HASH)?,
    };
    let out_path = match arguments.find(OUT)? {
        Some(path) => path.to_owned(),
        None => format!("{}{}", inputs[0], format.extension()),
    };
    Ok(SignRequest {
        format_name,
        format,
        inputs,
        level,
        hash_oid,
        out_path,
        is_detached,
        has_content_time_stamp,
    })
}

fn parse_level(text: &str) -> Result<SignatureLevel, UsageError> {
    match text.to_uppercase().as_str() {
        "B" => Ok(SignatureLevel::B),
        "T" => Ok(SignatureLevel::T),
        "LT" | "XL" | "X-LONG" => Ok(SignatureLevel::LT),
        other => Err(UsageError::UnknownLevel {
            level: other.to_owned(),
        }),
    }
}

// Each input under its file name; two inputs may not share one.
fn read_inputs(inputs: &[String]) -> Result<Vec<SignedFile>, CommandFailure> {
    let mut files: Vec<SignedFile> = Vec::new();
    for path in inputs {
        files.push(SignedFile {
            name: file_name(path),
            content: read_file(path)?,
        });
    }
    let mut names: Vec<&str> = files.iter().map(|file| file.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    if names.len() != files.len() {
        return Err(UsageError::DuplicateInputName.into());
    }
    Ok(files)
}

fn load_certificates(paths: &[String]) -> Result<Vec<Certificate>, CommandFailure> {
    let mut certificates = Vec::new();
    for path in paths {
        certificates.extend(certificate_files::load(Path::new(path))?);
    }
    Ok(certificates)
}

fn create_signature(
    request: &SignRequest<'_>,
    files: &[SignedFile],
    signer: SigningKey,
    services: SignatureServices<'_>,
) -> Result<Vec<u8>, CommandFailure> {
    let cades_options = CadesOptions {
        hash_oid: request.hash_oid.clone(),
        is_detached: request.is_detached || request.format == Format::AsicS,
        level: request.level,
        has_content_time_stamp: request.has_content_time_stamp,
        ..CadesOptions::default()
    };
    let file = &files[0];
    match request.format {
        Format::Cades => Ok(CadesSigner::new(signer, services).sign(&file.content, &cades_options)?),
        Format::AsicS => {
            let cades = CadesSigner::new(signer, services).sign(&file.content, &cades_options)?;
            Ok(asic_container::create_asic_s(&file.name, &file.content, &cades)?)
        }
        Format::Xades => {
            Ok(XadesSigner::new(signer, services).sign_to_bytes(files, &request.hash_oid, request.level)?)
        }
        Format::AsicE => {
            let xades = XadesSigner::new(signer, services).sign(files, &request.hash_oid, request.level)?;
            Ok(asic_container::create_asic_e(files, &xades)?)
        }
    }
}

// CAdES-B, CAdES-T, CAdES-X Long; XAdES-B-B, XAdES-B-T, XAdES-B-LT.
fn level_name(format: Format, level: SignatureLevel) -> &'static str {
    match (format.is_cades(), level) {
        (true, SignatureLevel::B) => "CAdES-B",
        (true, SignatureLevel::T) => "CAdES-T",
        (true, SignatureLevel::LT) => "CAdES-X Long",
        (false, SignatureLevel::B) => "XAdES-B-B",
        (false, SignatureLevel::T) => "XAdES-B-T",
        (false, SignatureLevel::LT) => "XAdES-B-LT",
    }
}
