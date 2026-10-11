use crate::errors::ServiceError;
use crate::x509::Certificate;

/// Downloads CA certificates named by authorityInfoAccess (caIssuers): DER, PEM or a CMS bundle (.p7b/.p7c).
pub trait CertificateSource {
    /// The certificates published at `url`.
    fn download_certificates(&self, url: &str) -> Result<Vec<Certificate>, ServiceError>;
}
