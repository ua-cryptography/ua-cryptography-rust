use rand_core::{OsRng, RngCore};

use crate::errors::ServiceError;
use crate::ocsp::OcspResponse;
use crate::services::{OcspService, pki_http};
use crate::x509::Certificate;

/// The bytes of an OCSP request nonce.
const NONCE_BYTES: usize = 16;
/// The media type of an OCSPRequest.
const REQUEST_MEDIA_TYPE: &str = "application/ocsp-request";

/// OCSP over HTTP. The responder is the URL from the certificate's authorityInfoAccess, unless an override is given.
#[derive(Debug)]
pub struct HttpOcspService {
    override_url: Option<String>,
    agent: ureq::Agent,
}

impl HttpOcspService {
    /// Asks the responder each certificate names, or always `override_url` when given.
    pub fn new(override_url: Option<&str>) -> Self {
        Self {
            override_url: override_url.map(str::to_owned),
            agent: pki_http::create_agent(),
        }
    }
}

impl OcspService for HttpOcspService {
    fn find_response(
        &self,
        certificate: &Certificate,
        issuer: &Certificate,
        hash_oid: &str,
    ) -> Result<Option<OcspResponse>, ServiceError> {
        let url = match &self.override_url {
            Some(url) => url.clone(),
            None => match certificate.ocsp_urls().into_iter().next() {
                Some(url) => url,
                None => return Ok(None),
            },
        };
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let request = OcspResponse::create_request(certificate, issuer, hash_oid, &nonce)?;
        let response = pki_http::post(&self.agent, &url, &request, REQUEST_MEDIA_TYPE)?;
        Ok(Some(OcspResponse::load(&response)?))
    }
}
