//! `keygen`: a JKS key store with a new DSTU 4145 key on a curve of table Г.1 and a self-signed certificate.

use std::io::Write;

use time::{Duration, OffsetDateTime};
use ua_pki::{
    Certificate, CertificateBuilder, DistinguishedName, Dstu4145PrivateKey, JksKeyStore, KeyUsageFlags, algorithms,
};

use crate::arguments::Arguments;
use crate::errors::{CommandFailure, UsageError};
use crate::files::{check_writable, write_file};
use crate::passwords::{self, password_help};
use crate::{EXIT_VALID, report};

/// The command's help.
pub const HELP: &str = concat!(
    "ua-sign keygen --keystore PATH --subject DN [options]

  --keystore PATH           the JKS file to create
  --subject DN              certificate subject, e.g. \"CN=Name,O=Organization,C=UA\"
  --alias NAME              entry name (default: key)
  --curve M                 curve of table Г.1 of DSTU 4145: 163 167 173 179 191 233 257 307 367 431 (default: 257)
  --days N                  certificate validity in days (default: 365)
  --signature-hash NAME     hash of the certificate signature: dstu7564 (default) or gost34311
  --cert PATH               also write the certificate (DER) to this file
  --force                   overwrite existing files
",
    password_help!()
);

/// The options taking a value.
pub const OPTIONS: [&str; 10] = [
    KEYSTORE,
    SUBJECT,
    ALIAS,
    CURVE,
    DAYS,
    SIGNATURE_HASH,
    CERT,
    passwords::PASSWORD,
    passwords::PASSWORD_ENV,
    passwords::PASSWORD_FILE,
];

/// The flags.
pub const FLAGS: [&str; 1] = [FORCE];

const KEYSTORE: &str = "keystore";
const SUBJECT: &str = "subject";
const ALIAS: &str = "alias";
const CURVE: &str = "curve";
const DAYS: &str = "days";
const SIGNATURE_HASH: &str = "signature-hash";
const CERT: &str = "cert";
const FORCE: &str = "force";
/// The entry name when none is given.
const DEFAULT_ALIAS: &str = "key";
/// The curve of the national PKI.
const DEFAULT_CURVE: u32 = 257;
/// A year of validity.
const DEFAULT_DAYS: u32 = 365;
/// The hash of the certificate signature when none is given.
const DEFAULT_SIGNATURE_HASH: &str = "dstu7564";

/// What `keygen` creates, read from the options.
struct KeyStoreRequest<'a> {
    path: &'a str,
    subject: DistinguishedName,
    alias: &'a str,
    m: u32,
    days: u32,
    signature_hash: String,
    certificate_path: Option<&'a str>,
}

/// Creates the key store (and the certificate file) the options name and describes what was created.
pub fn create_key_store(
    arguments: &Arguments,
    output: &mut dyn Write,
    environment: &dyn Fn(&str) -> Option<String>,
) -> Result<u8, CommandFailure> {
    let request = read_request(arguments)?;
    let is_forced = arguments.has_flag(FORCE);
    check_writable(request.path, is_forced)?;
    if let Some(certificate_path) = request.certificate_path {
        check_writable(certificate_path, is_forced)?;
    }
    let password = passwords::read_password(arguments, environment, true)?;
    if password.is_empty() {
        return Err(UsageError::EmptyPassword.into());
    }

    let domain = ua_dstu4145::get_polynomial_curve(request.m).map_err(|_| unknown_curve(request.m))?;
    let key = Dstu4145PrivateKey::generate(&domain);
    let certificate = create_self_signed_certificate(&request, &key)?;
    let mut store = JksKeyStore::new();
    store.add_private_key(request.alias, &key, vec![certificate.clone()], &password)?;
    write_file(request.path, &store.save(&password)?)?;
    if let Some(certificate_path) = request.certificate_path {
        write_file(certificate_path, certificate.encoded())?;
    }

    writeln!(output, "Key store:   {}", request.path)?;
    writeln!(output, "Alias:       {}", request.alias)?;
    writeln!(
        output,
        "Key:         DSTU 4145, polynomial basis, m = {} (table Г.1)",
        request.m
    )?;
    report::describe_certificate(&certificate, output, "Certificate: ")?;
    if let Some(certificate_path) = request.certificate_path {
        writeln!(output, "Written:     {certificate_path}")?;
    }
    writeln!(
        output,
        "The certificate is self-signed: signatures verify, but they are not qualified."
    )?;
    Ok(EXIT_VALID)
}

fn read_request(arguments: &Arguments) -> Result<KeyStoreRequest<'_>, CommandFailure> {
    let path = arguments.get(KEYSTORE)?;
    let subject = DistinguishedName::parse(arguments.get(SUBJECT)?)?;
    let alias = match arguments.find(ALIAS)? {
        Some(alias) => alias,
        None => DEFAULT_ALIAS,
    };
    let m = arguments.get_positive_number(CURVE, DEFAULT_CURVE)?;
    if !ua_dstu4145::POLYNOMIAL_DEGREES.contains(&m) {
        return Err(unknown_curve(m).into());
    }
    let days = arguments.get_positive_number(DAYS, DEFAULT_DAYS)?;
    let hash_name = match arguments.find(SIGNATURE_HASH)? {
        Some(name) => name,
        None => DEFAULT_SIGNATURE_HASH,
    };
    Ok(KeyStoreRequest {
        path,
        subject,
        alias,
        m,
        days,
        signature_hash: algorithms::parse_hash_name(hash_name)?,
        certificate_path: arguments.find(CERT)?,
    })
}

// Not a CA, digitalSignature and nonRepudiation, a subject key identifier.
fn create_self_signed_certificate(
    request: &KeyStoreRequest<'_>,
    key: &Dstu4145PrivateKey,
) -> Result<Certificate, CommandFailure> {
    let usage = KeyUsageFlags(KeyUsageFlags::DIGITAL_SIGNATURE.0 | KeyUsageFlags::NON_REPUDIATION.0);
    let mut builder = CertificateBuilder::new(request.subject.clone(), key.public_key().clone())?
        .add_basic_constraints(false)
        .add_key_usage(usage)
        .add_subject_key_identifier();
    builder.not_after = OffsetDateTime::now_utc() + Duration::days(i64::from(request.days));
    builder.signature_algorithm = algorithms::signature_algorithm_for(&request.signature_hash)?.to_owned();
    Ok(builder.self_sign(key)?)
}

fn unknown_curve(m: u32) -> UsageError {
    UsageError::UnknownCurve {
        m,
        known: ua_dstu4145::POLYNOMIAL_DEGREES.to_vec(),
    }
}
