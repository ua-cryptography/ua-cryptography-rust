//! Builds and checks certification paths (a subset of RFC 5280, section 6): each certificate is signed by the next,
//! is valid at the validation time, CA certificates are CAs, the path ends at a trust anchor, and every certificate
//! below the anchor has a "good" OCSP response from a responder of its issuer.

use time::OffsetDateTime;

use crate::errors::ServiceError;
use crate::ocsp::{OcspCertificateStatus, OcspResponse, OcspSingleResponse};
use crate::oids;
use crate::services::CertificateSource;
use crate::time_text;
use crate::validation::{CertificatePath, RevocationStatus, ValidationOptions, VerificationReport};
use crate::x509::Certificate;

/// The longest path built.
const MAX_DEPTH: usize = 10;

/// The path from `leaf` upwards: each next certificate is one whose subject is the issuer and whose key verifies the
/// signature. The path stops at a trust anchor, at a self-signed certificate or where no issuer is found; with
/// `downloads`, missing issuers are looked for at the caIssuers addresses.
pub fn build_chain(
    leaf: &Certificate,
    pool: &[Certificate],
    anchors: &[Certificate],
    downloads: Option<&dyn CertificateSource>,
) -> Vec<Certificate> {
    let mut candidates: Vec<Certificate> = anchors.iter().chain(pool).cloned().collect();
    let mut chain = vec![leaf.clone()];
    while chain.len() < MAX_DEPTH {
        let current = &chain[chain.len() - 1];
        if anchors.contains(current) || is_self_signed(current) {
            break;
        }
        let mut issuer = find_issuer(current, &candidates);
        if issuer.is_none() {
            if let Some(downloads) = downloads {
                candidates.extend(download_issuers(current, downloads));
                issuer = find_issuer(current, &candidates);
            }
        }
        match issuer {
            Some(issuer) if !chain.contains(&issuer) => chain.push(issuer),
            _ => break,
        }
    }
    chain
}

/// The certificates published at the caIssuers addresses of `certificate`; a download that fails is skipped (what
/// stays missing is reported by the caller). Providers publish their whole set there — the CA, its time-stamping and
/// OCSP services — so it also completes a time-stamp token that carries no certificate.
pub fn download_issuers(certificate: &Certificate, downloads: &dyn CertificateSource) -> Vec<Certificate> {
    let mut found = Vec::new();
    for url in certificate.ca_issuer_urls() {
        if let Ok(certificates) = downloads.download_certificates(&url) {
            found.extend(certificates);
        }
    }
    found
}

/// Validates the path of `leaf` at `time` and adds the checks to `report`, named after `name`. `revocation` is the
/// revocation data the signature carries. Returns the path.
pub fn validate(
    leaf: &Certificate,
    pool: &[Certificate],
    revocation: &[OcspResponse],
    options: &ValidationOptions<'_>,
    time: OffsetDateTime,
    report: &mut VerificationReport,
    name: &str,
) -> Vec<Certificate> {
    let pool: Vec<Certificate> = pool.iter().chain(&options.extra_certificates).cloned().collect();
    let chain = build_chain(leaf, &pool, &options.trust_anchors, options.downloads);
    report.paths.push(CertificatePath {
        name: name.to_owned(),
        certificates: chain.clone(),
    });
    let path_text: Vec<String> = chain
        .iter()
        .map(|certificate| format!("'{}'", short(certificate)))
        .collect();
    report.pass(&format!("{name}: path"), &path_text.join(" → "));
    check_links(&chain, time, report, name);
    check_trust(&chain, options, report, name);

    // The revocation of every certificate below the top of the path (the top has no issuer to ask).
    for link in chain.windows(2) {
        let context = RevocationContext {
            revocation,
            pool: &pool,
            options,
            time,
            name,
        };
        check_revocation(&link[0], &link[1], &context, report);
    }
    chain
}

/// The common name of a certificate's subject, or the whole subject.
pub fn short(certificate: &Certificate) -> String {
    match certificate.subject().find_attribute(oids::COMMON_NAME) {
        Some(common_name) => common_name.to_owned(),
        None => certificate.subject().to_string(),
    }
}

/// What the revocation check of one link needs besides the link.
struct RevocationContext<'a, 'b> {
    revocation: &'a [OcspResponse],
    pool: &'a [Certificate],
    options: &'a ValidationOptions<'b>,
    time: OffsetDateTime,
    name: &'a str,
}

fn is_self_signed(certificate: &Certificate) -> bool {
    certificate.is_self_issued() && certificate.is_signed_by(certificate)
}

// The candidates named as the issuer, those whose key identifier matches the authorityKeyIdentifier first; the first
// whose key verifies the certificate.
fn find_issuer(certificate: &Certificate, candidates: &[Certificate]) -> Option<Certificate> {
    let authority_key = certificate.authority_key_identifier();
    let mut named: Vec<&Certificate> = candidates
        .iter()
        .filter(|candidate| *candidate != certificate && candidate.subject() == certificate.issuer())
        .collect();
    let has_matching_key =
        |candidate: &Certificate| authority_key.is_some() && candidate.subject_key_identifier() == authority_key;
    named.sort_by_key(|candidate| !has_matching_key(candidate));
    named
        .into_iter()
        .find(|candidate| certificate.is_signed_by(candidate))
        .cloned()
}

// Signatures, validity and CA flags along the path.
fn check_links(chain: &[Certificate], time: OffsetDateTime, report: &mut VerificationReport, name: &str) {
    for (index, certificate) in chain.iter().enumerate() {
        if let Some(issuer) = chain.get(index + 1) {
            report.check(
                &format!("{name}: signature of '{}'", short(certificate)),
                certificate.is_signed_by(issuer),
                &format!("issued by '{}'", short(issuer)),
            );
        }
        if !certificate.is_valid_at(time) {
            let details = format!(
                "{} – {} does not include {} UTC",
                time_text::format_date(certificate.not_before()),
                time_text::format_date(certificate.not_after()),
                time_text::format_minutes(time)
            );
            report.fail(&format!("{name}: validity of '{}'", short(certificate)), &details);
        }
        if index > 0 && !certificate.is_ca() {
            let details = "issues certificates but is not a CA (basicConstraints)";
            report.fail(&format!("{name}: '{}'", short(certificate)), details);
        }
    }
}

fn check_trust(chain: &[Certificate], options: &ValidationOptions<'_>, report: &mut VerificationReport, name: &str) {
    let top = &chain[chain.len() - 1];
    let is_top_self_signed = is_self_signed(top);
    let check = format!("{name}: trust");
    if options.trust_anchors.is_empty() {
        let details = if is_top_self_signed {
            format!("ends at the self-signed '{}'; no trusted roots were given", short(top))
        } else {
            format!("incomplete: the issuer of '{}' is not available", short(top))
        };
        report.warn(&check, &details);
        return;
    }
    let is_trusted = options.trust_anchors.contains(top);
    let details = if is_trusted {
        format!("ends at the trusted '{}'", short(top))
    } else if is_top_self_signed {
        format!("ends at '{}', which is not a trusted root", short(top))
    } else {
        format!("the issuer of '{}' is not available", short(top))
    };
    report.check(&check, is_trusted, &details);
}

fn check_revocation(
    certificate: &Certificate,
    issuer: &Certificate,
    context: &RevocationContext<'_, '_>,
    report: &mut VerificationReport,
) {
    let check = format!("{}: revocation of '{}'", context.name, short(certificate));
    let found = match find_revocation(certificate, issuer, context) {
        Ok(Some(found)) => found,
        Ok(None) => {
            report.warn(&check, "no OCSP response (the signature has no revocation data)");
            return;
        }
        Err(error) => {
            report.warn(&check, &format!("the OCSP request failed: {error}"));
            return;
        }
    };
    let mut known: Vec<Certificate> = context.pool.to_vec();
    known.push(issuer.clone());
    let Some(responder) = found.response.find_responder(&known) else {
        report.fail(&check, "the OCSP responder's certificate is not available");
        return;
    };
    if !found.response.is_signed_by(&responder) {
        report.fail(
            &check,
            &format!("the OCSP response is not signed by '{}'", short(&responder)),
        );
        return;
    }
    if !is_responder_of(&responder, issuer) {
        let details = format!(
            "'{}' is not an OCSP responder of '{}'",
            short(&responder),
            short(issuer)
        );
        report.fail(&check, &details);
        return;
    }
    report_status(&check, &found.status, &responder, found.is_online, found.time, report);
    report.revocations.push(RevocationStatus {
        path: context.name.to_owned(),
        certificate: certificate.clone(),
        response: found.response,
        status: found.status,
        responder,
        is_online: found.is_online,
    });
}

/// An OCSP answer about one certificate and the time its status is judged at.
struct FoundRevocation {
    response: OcspResponse,
    status: OcspSingleResponse,
    is_online: bool,
    time: OffsetDateTime,
}

// The embedded response about the certificate, else one asked online (judged "now"); none when there is neither.
fn find_revocation(
    certificate: &Certificate,
    issuer: &Certificate,
    context: &RevocationContext<'_, '_>,
) -> Result<Option<FoundRevocation>, ServiceError> {
    let embedded = context.revocation.iter().find_map(|response| {
        let status = response.find(certificate, issuer)?.clone();
        Some(FoundRevocation {
            response: response.clone(),
            status,
            is_online: false,
            time: context.time,
        })
    });
    if embedded.is_some() {
        return Ok(embedded);
    }
    let Some(online) = context.options.online_ocsp else {
        return Ok(None);
    };
    let Some(response) = online.find_response(certificate, issuer, oids::DSTU7564_256)? else {
        return Ok(None);
    };
    let Some(status) = response.find(certificate, issuer).cloned() else {
        return Ok(None);
    };
    Ok(Some(FoundRevocation {
        response,
        status,
        is_online: true,
        time: context.options.now(),
    }))
}

// The issuer itself, or a certificate the issuer gave the OCSPSigning purpose.
fn is_responder_of(responder: &Certificate, issuer: &Certificate) -> bool {
    responder == issuer
        || (responder.is_signed_by(issuer)
            && responder
                .extended_key_usage()
                .iter()
                .any(|purpose| purpose == oids::KEY_PURPOSE_OCSP_SIGNING))
}

fn report_status(
    check: &str,
    status: &OcspSingleResponse,
    responder: &Certificate,
    is_online: bool,
    time: OffsetDateTime,
    report: &mut VerificationReport,
) {
    let source = if is_online { "online" } else { "embedded" };
    let at = format!(
        "{source} response of '{}' at {} UTC",
        short(responder),
        time_text::format_minutes(status.this_update)
    );
    let revoked_on = |revocation_time: Option<OffsetDateTime>| match revocation_time {
        Some(revoked) => time_text::format_minutes(revoked),
        None => String::new(),
    };
    match status.status {
        OcspCertificateStatus::Good => report.pass(check, &format!("good, {at}")),
        OcspCertificateStatus::Revoked if status.revocation_time.is_some_and(|revoked| revoked > time) => {
            let details = format!(
                "revoked on {} UTC, after the validation time; {at}",
                revoked_on(status.revocation_time)
            );
            report.pass(check, &details);
        }
        OcspCertificateStatus::Revoked => {
            report.fail(
                check,
                &format!("revoked on {} UTC; {at}", revoked_on(status.revocation_time)),
            );
        }
        OcspCertificateStatus::Unknown => report.fail(check, &format!("unknown to the responder; {at}")),
    }
}
