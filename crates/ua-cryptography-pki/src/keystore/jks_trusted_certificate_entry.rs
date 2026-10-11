use time::OffsetDateTime;

use crate::x509::Certificate;

/// A TrustedCertEntry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JksTrustedCertificateEntry {
    /// The alias.
    pub alias: String,
    /// When the entry was created.
    pub created: OffsetDateTime,
    /// The certificate.
    pub certificate: Certificate,
}
