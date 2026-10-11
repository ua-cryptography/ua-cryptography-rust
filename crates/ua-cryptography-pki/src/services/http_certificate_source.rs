use crate::errors::ServiceError;
use crate::services::{CertificateSource, certificate_files, pki_http};
use crate::x509::Certificate;

/// Downloads certificates over HTTP: DER, PEM or a CMS bundle.
#[derive(Debug)]
pub struct HttpCertificateSource {
    agent: ureq::Agent,
}

impl HttpCertificateSource {
    /// A source with the services' timeout and response cap.
    pub fn new() -> Self {
        Self {
            agent: pki_http::create_agent(),
        }
    }
}

impl Default for HttpCertificateSource {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateSource for HttpCertificateSource {
    fn download_certificates(&self, url: &str) -> Result<Vec<Certificate>, ServiceError> {
        Ok(certificate_files::parse(&pki_http::get(&self.agent, url)?)?)
    }
}
