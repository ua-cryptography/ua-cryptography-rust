use crate::x509::Certificate;

/// A certification path built for `name` (e.g. "signer"), from the certificate up to the top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificatePath {
    /// Whose path it is, e.g. "signer" or "signature time-stamp service".
    pub name: String,
    /// The certificates, the end entity first.
    pub certificates: Vec<Certificate>,
}
