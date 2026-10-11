//! The network clients of the PKI services an operation needs; the browser build has none and refuses the need.

use ua_pki::{CertificateSource, OcspService, TimeStampService};

use crate::errors::OperationFailure;

/// The clients of the time-stamping, OCSP and caIssuers services one operation asked for.
#[cfg(not(target_arch = "wasm32"))]
pub struct ServiceClients {
    time_stamps: Option<ua_pki::HttpTimeStampService>,
    ocsp: Option<ua_pki::HttpOcspService>,
    downloads: Option<ua_pki::HttpCertificateSource>,
}

#[cfg(not(target_arch = "wasm32"))]
impl ServiceClients {
    /// The time-stamping service at `tsa_url` when given; with `is_long_term`, the OCSP responders (`ocsp_url` for
    /// all, else each certificate's) and caIssuers downloads.
    pub fn connect(
        tsa_url: Option<&str>,
        is_long_term: bool,
        ocsp_url: Option<&str>,
    ) -> Result<Self, OperationFailure> {
        Ok(Self {
            time_stamps: tsa_url.map(ua_pki::HttpTimeStampService::new),
            ocsp: is_long_term.then(|| ua_pki::HttpOcspService::new(ocsp_url)),
            downloads: is_long_term.then(ua_pki::HttpCertificateSource::new),
        })
    }

    /// The time-stamping service, when asked for.
    pub fn time_stamps(&self) -> Option<&dyn TimeStampService> {
        self.time_stamps.as_ref().map(|client| client as &dyn TimeStampService)
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

/// No clients: the browser build reaches no network.
#[cfg(target_arch = "wasm32")]
pub struct ServiceClients;

#[cfg(target_arch = "wasm32")]
impl ServiceClients {
    /// Refuses whatever needs a service.
    pub fn connect(
        tsa_url: Option<&str>,
        is_long_term: bool,
        _ocsp_url: Option<&str>,
    ) -> Result<Self, OperationFailure> {
        if tsa_url.is_some() || is_long_term {
            return Err(OperationFailure::invalid_argument(
                "The browser build reaches no time-stamping, OCSP or caIssuers service: sign at level B and \
                 verify offline.",
            ));
        }
        Ok(Self)
    }

    /// None.
    pub fn time_stamps(&self) -> Option<&dyn TimeStampService> {
        None
    }

    /// None.
    pub fn ocsp(&self) -> Option<&dyn OcspService> {
        None
    }

    /// None.
    pub fn downloads(&self) -> Option<&dyn CertificateSource> {
        None
    }
}
