//! The HTTP clients of the PKI services an operation needs: the native platforms reach them over sockets.

use ua_cryptography_operations::models::SigningPlan;
use ua_cryptography_pki::{
    CertificateSource, HttpCertificateSource, HttpOcspService, HttpTimeStampService, OcspService, SignatureServices,
    TimeStampService,
};

/// The clients of the time-stamping, OCSP and caIssuers services one operation asked for.
pub struct ServiceClients {
    time_stamps: Option<HttpTimeStampService>,
    ocsp: Option<HttpOcspService>,
    downloads: Option<HttpCertificateSource>,
}

impl ServiceClients {
    /// The time-stamping service of `plan` when it needs one; for level LT, the OCSP responders (`ocsp_url` for all,
    /// else each certificate's) and caIssuers downloads.
    pub fn for_signing(plan: &SigningPlan, ocsp_url: Option<&str>) -> Self {
        Self {
            time_stamps: plan.tsa_url.as_deref().map(HttpTimeStampService::new),
            ocsp: plan.is_long_term.then(|| HttpOcspService::new(ocsp_url)),
            downloads: plan.is_long_term.then(HttpCertificateSource::new),
        }
    }

    /// Each certificate's OCSP responder and caIssuers downloads when `is_online`, else none.
    pub fn for_verification(is_online: bool) -> Self {
        Self {
            time_stamps: None,
            ocsp: is_online.then(|| HttpOcspService::new(None)),
            downloads: is_online.then(HttpCertificateSource::new),
        }
    }

    /// The services a signer of `plan` uses: these clients and the plan's CA certificates.
    pub fn signature_services(&self, plan: &SigningPlan) -> SignatureServices<'_> {
        SignatureServices {
            time_stamps: self.time_stamps.as_ref().map(|client| client as &dyn TimeStampService),
            ocsp: self.ocsp(),
            downloads: self.downloads(),
            extra_certificates: plan.extra_certificates.clone(),
        }
    }

    /// The OCSP service, when asked for.
    pub fn ocsp(&self) -> Option<&dyn OcspService> {
        self.ocsp.as_ref().map(|client| client as &dyn OcspService)
    }

    /// The caIssuers downloads, when asked for.
    pub fn downloads(&self) -> Option<&dyn CertificateSource> {
        self.downloads.as_ref().map(|client| client as &dyn CertificateSource)
    }
}
