use crate::errors::ServiceError;
use crate::services::{TimeStampService, pki_http};
use crate::tsp::{TimeStampToken, time_stamp_protocol};

/// An RFC 3161 time-stamping service over HTTP: a request with a fresh nonce, the answer checked against it.
#[derive(Debug)]
pub struct HttpTimeStampService {
    url: String,
    agent: ureq::Agent,
}

impl HttpTimeStampService {
    /// The service at `url` (30 s timeout, answers up to 10 MiB).
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            agent: pki_http::create_agent(),
        }
    }

    /// The service URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl TimeStampService for HttpTimeStampService {
    fn get_token(&self, hash: &[u8], hash_oid: &str) -> Result<TimeStampToken, ServiceError> {
        let nonce = time_stamp_protocol::create_nonce();
        let request = time_stamp_protocol::create_request(hash, hash_oid, &nonce, None);
        let response = pki_http::post(
            &self.agent,
            &self.url,
            &request,
            time_stamp_protocol::REQUEST_MEDIA_TYPE,
        )?;
        Ok(time_stamp_protocol::parse_response(&response, hash, hash_oid, &nonce)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms;

    #[test]
    fn an_unreachable_service_is_a_transport_failure() {
        let service = HttpTimeStampService::new("http://127.0.0.1:1/tsp");
        let hash = algorithms::hash(crate::oids::DSTU7564_256, b"", None).unwrap();
        let failure = service.get_token(&hash, crate::oids::DSTU7564_256).unwrap_err();
        assert!(matches!(failure, ServiceError::Transport { .. }), "{failure}");
    }
}
