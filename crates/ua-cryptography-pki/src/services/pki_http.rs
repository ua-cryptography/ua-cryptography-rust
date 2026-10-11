//! HTTP transport shared by the services: POST of DER bodies (RFC 3161, 3.4; RFC 6960, appendix A) and GET of
//! certificates, with a timeout and a cap on the answer's size.

use std::io::Read;
use std::time::Duration;

use crate::errors::ServiceError;

/// The largest answer accepted: time-stamps, OCSP responses and CA certificates are a few kilobytes.
pub(crate) const MAX_RESPONSE_BYTES: usize = 10 << 20;
/// The time a whole request may take.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The User-Agent header.
const USER_AGENT: &str = "UA.Cryptography.Pki";

/// An HTTP agent with the services' timeout and User-Agent.
pub(crate) fn create_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(TIMEOUT)
        .user_agent(USER_AGENT)
        .build()
}

/// POSTs `body` with Content-Type `media_type` and returns the answer's body.
pub(crate) fn post(agent: &ureq::Agent, url: &str, body: &[u8], media_type: &str) -> Result<Vec<u8>, ServiceError> {
    let response = agent.post(url).set("Content-Type", media_type).send_bytes(body);
    read_answer(url, response)
}

/// GETs `url` and returns the answer's body.
pub(crate) fn get(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, ServiceError> {
    read_answer(url, agent.get(url).call())
}

fn read_answer(url: &str, response: Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>, ServiceError> {
    let response = match response {
        Ok(response) => response,
        Err(ureq::Error::Status(status, response)) => {
            return Err(ServiceError::Status {
                url: url.to_owned(),
                status,
                reason: response.status_text().to_owned(),
            });
        }
        Err(ureq::Error::Transport(transport)) => return Err(transport_error(url, &transport)),
    };
    let mut body = Vec::new();
    let limit = (MAX_RESPONSE_BYTES + 1) as u64;
    response
        .into_reader()
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|error| ServiceError::Transport {
            url: url.to_owned(),
            message: error.to_string(),
        })?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ServiceError::TooLarge {
            url: url.to_owned(),
            max_bytes: MAX_RESPONSE_BYTES,
        });
    }
    Ok(body)
}

fn transport_error(url: &str, transport: &ureq::Transport) -> ServiceError {
    // ureq's own Display starts with the URL, which ServiceError already prints.
    let message = match transport.message() {
        Some(detail) => format!("{}: {detail}", transport.kind()),
        None => transport.kind().to_string(),
    };
    ServiceError::Transport {
        url: url.to_owned(),
        message,
    }
}
