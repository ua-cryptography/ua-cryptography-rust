//! Prints a verification result — every signature, its signer and times, and each check — as text or as an INI report
//! with everything the checks were made on; and the lines that describe a certificate.

use std::io::Write;

use num_bigint::BigInt;
use time::{OffsetDateTime, UtcOffset};
use ua_cryptography_gf2m::FieldBasis;
use ua_cryptography_pki::{
    Certificate, CertificatePath, CheckStatus, KeyError, RevocationStatus, SignedObject, TimeStampDetails,
    VerificationCheck, VerificationReport, VerificationResult, algorithms, signature_verifier,
};

use crate::errors::CommandFailure;

/// The section of the container's structure checks in the INI report.
const CONTAINER_SECTION: &str = "container";

/// Writes the result as text: per signature its signer, times and checks (`is_quiet`: the failed and warned ones
/// only), then the verdict.
pub fn write_text(
    path: &str,
    result: &VerificationResult,
    output: &mut dyn Write,
    is_quiet: bool,
) -> std::io::Result<()> {
    writeln!(output, "File:      {path} — {}", result.format)?;
    for report in &result.signatures {
        writeln!(output)?;
        match &report.format {
            Some(format) => writeln!(output, "{} — {format}", report.title)?,
            None => writeln!(output, "{}", report.title)?,
        }
        if let Some(signer) = &report.signer {
            writeln!(output, "  Signer:     {}", signer.subject())?;
            writeln!(output, "  Issuer:     {}", signer.issuer())?;
        }
        if let Some(claimed) = report.claimed_signing_time {
            writeln!(
                output,
                "  Signed at:  {} UTC (claimed by the signer)",
                format_date_time(claimed)
            )?;
        }
        if let Some(stamped) = report.time_stamp_time {
            writeln!(output, "  Time-stamp: {} UTC", format_date_time(stamped))?;
        }
        for check in report
            .checks
            .iter()
            .filter(|check| !is_quiet || check.status != CheckStatus::Passed)
        {
            writeln!(
                output,
                "  {} {}: {}",
                text_mark(check.status),
                check.name,
                check.details
            )?;
        }
        writeln!(output, "  => {}", verdict(report))?;
    }
    let warnings = count_checks(&result.signatures, CheckStatus::Warning);
    writeln!(output)?;
    match (result.is_valid(), warnings) {
        (false, _) => writeln!(output, "Result: INVALID"),
        (true, 0) => writeln!(output, "Result: VALID"),
        (true, 1) => writeln!(output, "Result: VALID (1 warning)"),
        (true, _) => writeln!(output, "Result: VALID ({warnings} warnings)"),
    }
}

/// Writes the result as INI: [summary], then for the container and each signature its properties, signer, signed
/// references, time-stamps, certification paths, OCSP statuses and checks. Times are UTC in ISO 8601; digests and
/// serial numbers are hex; algorithms are a name followed by the identifier in parentheses.
pub fn write_ini(
    path: &str,
    result: &VerificationResult,
    output: &mut dyn Write,
    verified_at: OffsetDateTime,
) -> Result<(), CommandFailure> {
    let mut ini = IniWriter { output };
    writeln!(ini.output, "; ua-sign verification report")?;
    write_summary(&mut ini, path, result, verified_at)?;
    let mut number = 0;
    for report in &result.signatures {
        let section = if report.title == signature_verifier::CONTAINER_TITLE {
            CONTAINER_SECTION.to_owned()
        } else {
            number += 1;
            format!("signature.{number}")
        };
        write_properties(&mut ini, &section, report, verified_at)?;
        if let Some(signer) = &report.signer {
            write_signer(&mut ini, &section, signer)?;
        }
        write_references(&mut ini, &section, &report.signed_objects)?;
        write_time_stamps(&mut ini, &section, &report.time_stamps)?;
        write_paths(&mut ini, &section, &report.paths)?;
        write_revocations(&mut ini, &section, &report.revocations)?;
        write_checks(&mut ini, &section, &report.checks)?;
    }
    Ok(())
}

/// Writes the lines that describe a certificate: subject, issuer, serial and validity, key, service addresses. The
/// first line starts with `indent`, the others with as many spaces.
pub fn describe_certificate(
    certificate: &Certificate,
    output: &mut dyn Write,
    indent: &str,
) -> Result<(), CommandFailure> {
    let pad = " ".repeat(indent.chars().count());
    writeln!(output, "{indent}{}", certificate.subject())?;
    writeln!(output, "{pad}issuer {}", certificate.issuer())?;
    writeln!(
        output,
        "{pad}serial {}, valid {} – {}",
        serial(certificate.serial_number()),
        format_date(certificate.not_before()),
        format_date(certificate.not_after())
    )?;
    writeln!(output, "{pad}{}", describe_key(certificate)?)?;
    for url in certificate.ocsp_urls() {
        writeln!(output, "{pad}OCSP {url}")?;
    }
    for url in certificate.time_stamp_urls() {
        writeln!(output, "{pad}TSP  {url}")?;
    }
    Ok(())
}

/// A serial number in uppercase hex without leading zeros.
pub fn serial(serial_number: &BigInt) -> String {
    format!("{serial_number:X}").trim_start_matches('0').to_owned()
}

/// The certificate's key: "DSTU 4145 key, PB m = 257, with DKE", or the algorithm of a key of another kind.
pub fn describe_key(certificate: &Certificate) -> Result<String, KeyError> {
    if !certificate.has_dstu4145_key() {
        return Ok(format!("key algorithm {}", certificate.public_key_algorithm()));
    }
    let key = certificate.public_key()?;
    let field = key.domain().field();
    let basis = match field.basis() {
        FieldBasis::Polynomial(_) => "PB",
        FieldBasis::OptimalNormal(_) => "ONB",
    };
    let dke = if key.dke().is_some() { ", with DKE" } else { "" };
    Ok(format!("DSTU 4145 key, {basis} m = {}{dke}", field.m()))
}

/// A date as yyyy-MM-dd (UTC).
pub fn format_date(time: OffsetDateTime) -> String {
    let utc = time.to_offset(UtcOffset::UTC);
    format!("{:04}-{:02}-{:02}", utc.year(), u8::from(utc.month()), utc.day())
}

/// The lines of the INI report: `[section]` after an empty line, `key=value` with line breaks escaped.
struct IniWriter<'a> {
    output: &'a mut dyn Write,
}

impl IniWriter<'_> {
    fn section(&mut self, name: &str) -> std::io::Result<()> {
        writeln!(self.output)?;
        writeln!(self.output, "[{name}]")
    }

    fn value(&mut self, key: &str, value: &str) -> std::io::Result<()> {
        let escaped = value.replace('\r', "").replace('\n', "\\n");
        writeln!(self.output, "{key}={escaped}")
    }

    fn optional_value(&mut self, key: &str, value: Option<&str>) -> std::io::Result<()> {
        match value {
            Some(value) => self.value(key, value),
            None => Ok(()),
        }
    }
}

fn write_summary(
    ini: &mut IniWriter<'_>,
    path: &str,
    result: &VerificationResult,
    verified_at: OffsetDateTime,
) -> std::io::Result<()> {
    let signature_count = result
        .signatures
        .iter()
        .filter(|report| report.title != signature_verifier::CONTAINER_TITLE)
        .count();
    ini.section("summary")?;
    ini.value("file", path)?;
    ini.value("format", &result.format)?;
    ini.value("result", if result.is_valid() { "VALID" } else { "INVALID" })?;
    ini.value("signatures", &signature_count.to_string())?;
    ini.value(
        "warnings",
        &count_checks(&result.signatures, CheckStatus::Warning).to_string(),
    )?;
    ini.value(
        "failures",
        &count_checks(&result.signatures, CheckStatus::Failed).to_string(),
    )?;
    ini.value("verified_at", &format_time(verified_at))?;
    for (index, file) in result.signed_files.iter().enumerate() {
        ini.value(&format!("signed_file.{}", index + 1), &file.name)?;
    }
    Ok(())
}

fn write_properties(
    ini: &mut IniWriter<'_>,
    section: &str,
    report: &VerificationReport,
    now: OffsetDateTime,
) -> std::io::Result<()> {
    ini.section(section)?;
    ini.value("title", &report.title)?;
    ini.optional_value("level", report.level.as_deref())?;
    ini.optional_value("packaging", report.packaging.as_deref())?;
    let signature_algorithm = report.signature_algorithm.as_deref().map(signature_algorithm);
    ini.optional_value("signature_algorithm", signature_algorithm.as_deref())?;
    let digest_algorithm = report.digest_algorithm.as_deref().map(hash_algorithm);
    ini.optional_value("digest_algorithm", digest_algorithm.as_deref())?;
    ini.optional_value("signing_time", report.claimed_signing_time.map(format_time).as_deref())?;
    ini.optional_value("timestamp_time", report.time_stamp_time.map(format_time).as_deref())?;
    if report.signer.is_some() {
        ini.value("validation_time", &format_time(report.validation_time(now)))?;
    }
    ini.value("result", verdict(report))?;
    ini.value(
        "warnings",
        &count_checks(std::slice::from_ref(report), CheckStatus::Warning).to_string(),
    )?;
    ini.value(
        "failures",
        &count_checks(std::slice::from_ref(report), CheckStatus::Failed).to_string(),
    )
}

fn write_signer(ini: &mut IniWriter<'_>, section: &str, signer: &Certificate) -> Result<(), CommandFailure> {
    ini.section(&format!("{section}.signer"))?;
    ini.value("subject", &signer.subject().to_string())?;
    ini.value("issuer", &signer.issuer().to_string())?;
    ini.value("serial", &serial(signer.serial_number()))?;
    ini.value("valid_from", &format_time(signer.not_before()))?;
    ini.value("valid_to", &format_time(signer.not_after()))?;
    ini.value("key", &describe_key(signer)?)?;
    ini.value(
        "certificate_signature_algorithm",
        &signature_algorithm(signer.signature_algorithm()),
    )?;
    Ok(())
}

fn write_references(ini: &mut IniWriter<'_>, section: &str, signed_objects: &[SignedObject]) -> std::io::Result<()> {
    for (index, signed) in signed_objects.iter().enumerate() {
        ini.section(&format!("{section}.reference.{}", index + 1))?;
        ini.value("name", &signed.name)?;
        ini.value("digest_algorithm", &hash_algorithm(&signed.hash_algorithm))?;
        ini.value("digest", &hex_upper(&signed.digest))?;
    }
    Ok(())
}

fn write_time_stamps(ini: &mut IniWriter<'_>, section: &str, stamps: &[TimeStampDetails]) -> std::io::Result<()> {
    for (index, stamp) in stamps.iter().enumerate() {
        let token = &stamp.token;
        ini.section(&format!("{section}.timestamp.{}", index + 1))?;
        ini.value("kind", &stamp.kind)?;
        ini.value("time", &format_time(token.gen_time()))?;
        ini.value("serial", &serial(token.serial_number()))?;
        ini.value("policy", token.policy())?;
        ini.value("imprint_algorithm", &hash_algorithm(token.imprint_algorithm()))?;
        ini.value("imprint", &hex_upper(token.imprint()))?;
        if let Some(authority) = &stamp.authority {
            ini.value("authority", &authority.subject().to_string())?;
            ini.value("authority_serial", &serial(authority.serial_number()))?;
        }
    }
    Ok(())
}

fn write_paths(ini: &mut IniWriter<'_>, section: &str, paths: &[CertificatePath]) -> std::io::Result<()> {
    for (index, path) in paths.iter().enumerate() {
        ini.section(&format!("{section}.path.{}", index + 1))?;
        ini.value("for", &path.name)?;
        for (position, certificate) in path.certificates.iter().enumerate() {
            let key = format!("certificate.{}", position + 1);
            ini.value(&key, &certificate.subject().to_string())?;
            ini.value(&format!("{key}.serial"), &serial(certificate.serial_number()))?;
            ini.value(&format!("{key}.valid_from"), &format_time(certificate.not_before()))?;
            ini.value(&format!("{key}.valid_to"), &format_time(certificate.not_after()))?;
        }
    }
    Ok(())
}

fn write_revocations(ini: &mut IniWriter<'_>, section: &str, revocations: &[RevocationStatus]) -> std::io::Result<()> {
    for (index, revocation) in revocations.iter().enumerate() {
        let status = &revocation.status;
        ini.section(&format!("{section}.ocsp.{}", index + 1))?;
        ini.value("path", &revocation.path)?;
        ini.value("certificate", &revocation.certificate.subject().to_string())?;
        ini.value("serial", &serial(revocation.certificate.serial_number()))?;
        ini.value("status", &status.status.to_string())?;
        ini.optional_value("revocation_time", status.revocation_time.map(format_time).as_deref())?;
        ini.value("source", if revocation.is_online { "online" } else { "embedded" })?;
        ini.value("responder", &revocation.responder.subject().to_string())?;
        ini.value("produced_at", &format_time(revocation.response.produced_at()))?;
        ini.value("this_update", &format_time(status.this_update))?;
        ini.optional_value("next_update", status.next_update.map(format_time).as_deref())?;
    }
    Ok(())
}

fn write_checks(ini: &mut IniWriter<'_>, section: &str, checks: &[VerificationCheck]) -> std::io::Result<()> {
    ini.section(&format!("{section}.checks"))?;
    for (index, check) in checks.iter().enumerate() {
        let status = match check.status {
            CheckStatus::Passed => "OK",
            CheckStatus::Warning => "WARN",
            CheckStatus::Failed => "FAIL",
        };
        let line = format!("{status} | {} | {}", check.name, check.details);
        ini.value(&(index + 1).to_string(), &line)?;
    }
    Ok(())
}

fn text_mark(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Passed => "[ OK ]",
        CheckStatus::Warning => "[WARN]",
        CheckStatus::Failed => "[FAIL]",
    }
}

fn verdict(report: &VerificationReport) -> &'static str {
    match (report.is_valid(), report.has_warnings()) {
        (false, _) => "INVALID",
        (true, true) => "valid, with warnings",
        (true, false) => "valid",
    }
}

fn count_checks(reports: &[VerificationReport], status: CheckStatus) -> usize {
    reports
        .iter()
        .flat_map(|report| &report.checks)
        .filter(|check| check.status == status)
        .count()
}

// "DSTU 7564-256 (1.2.804.2.1.1.1.1.2.2.1)"; an identifier without a name stands alone.
fn hash_algorithm(identifier: &str) -> String {
    named_identifier(algorithms::hash_name(identifier), identifier)
}

fn signature_algorithm(identifier: &str) -> String {
    named_identifier(algorithms::signature_algorithm_name(identifier), identifier)
}

fn named_identifier(name: &str, identifier: &str) -> String {
    if name == identifier {
        identifier.to_owned()
    } else {
        format!("{name} ({identifier})")
    }
}

// yyyy-MM-ddTHH:mm:ssZ.
fn format_time(time: OffsetDateTime) -> String {
    let utc = time.to_offset(UtcOffset::UTC);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        format_date(utc),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

// yyyy-MM-dd HH:mm:ss.
fn format_date_time(time: OffsetDateTime) -> String {
    let utc = time.to_offset(UtcOffset::UTC);
    format!(
        "{} {:02}:{:02}:{:02}",
        format_date(utc),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_numbers_are_uppercase_hex_without_leading_zeros() {
        assert_eq!(serial(&BigInt::from(0x0A_FFi32)), "AFF");
        assert_eq!(serial(&BigInt::from(255u8)), "FF");
    }

    #[test]
    fn times_are_utc_in_iso_8601() {
        let time = time::macros::datetime!(2026-01-01 14:00:25 +02:00);
        assert_eq!(format_time(time), "2026-01-01T12:00:25Z");
        assert_eq!(format_date_time(time), "2026-01-01 12:00:25");
        assert_eq!(format_date(time), "2026-01-01");
    }

    #[test]
    fn an_algorithm_is_its_name_and_its_identifier() {
        assert_eq!(
            hash_algorithm(ua_cryptography_pki::oids::DSTU7564_256),
            "DSTU 7564-256 (1.2.804.2.1.1.1.1.2.2.1)"
        );
        assert_eq!(hash_algorithm("1.2.3"), "1.2.3");
    }

    #[test]
    fn ini_values_keep_to_one_line() {
        let mut output = Vec::new();
        IniWriter { output: &mut output }
            .value("details", "one\r\ntwo")
            .unwrap();
        assert_eq!(output, b"details=one\\ntwo\n");
    }
}
