//! What a certificate says.

use ua_pki::Certificate;

use crate::errors::OperationFailure;
use crate::models::reports::CertificateDetails;
use crate::utils::{describe_signature_algorithm, format_serial, format_time};

/// The details of a certificate given as DER, PEM or base64.
pub fn get_certificate_details(certificate: &[u8]) -> Result<CertificateDetails, OperationFailure> {
    Ok(describe_certificate(&Certificate::load(certificate)?))
}

/// The details of a parsed certificate.
pub fn describe_certificate(certificate: &Certificate) -> CertificateDetails {
    CertificateDetails {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        serial: format_serial(certificate.serial_number()),
        valid_from: format_time(certificate.not_before()),
        valid_to: format_time(certificate.not_after()),
        signature_algorithm: describe_signature_algorithm(certificate.signature_algorithm()),
        is_ca: certificate.is_ca(),
        ocsp_urls: certificate.ocsp_urls(),
        ca_issuer_urls: certificate.ca_issuer_urls(),
        time_stamp_urls: certificate.time_stamp_urls(),
    }
}
