use crate::errors::ServiceError;
use crate::tsp::TimeStampToken;

/// A time-stamping service (RFC 3161).
pub trait TimeStampService {
    /// A token whose message imprint is `hash`, computed with `hash_oid`; the token is checked to answer the request.
    fn get_token(&self, hash: &[u8], hash_oid: &str) -> Result<TimeStampToken, ServiceError>;
}
