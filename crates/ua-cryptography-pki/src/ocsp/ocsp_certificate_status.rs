use std::fmt;

/// certStatus of a SingleResponse (RFC 6960, 4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OcspCertificateStatus {
    /// good `[0]`.
    Good,
    /// revoked `[1]`.
    Revoked,
    /// unknown `[2]`.
    Unknown,
}

impl fmt::Display for OcspCertificateStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Good => "good",
            Self::Revoked => "revoked",
            Self::Unknown => "unknown",
        })
    }
}
