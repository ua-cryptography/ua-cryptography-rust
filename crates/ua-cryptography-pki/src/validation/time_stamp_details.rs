use crate::tsp::TimeStampToken;
use crate::x509::Certificate;

/// A time-stamp found on the signature: its kind (e.g. "signature time-stamp"), the token and the service's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampDetails {
    /// "signature time-stamp" or "content time-stamp".
    pub kind: String,
    /// The token.
    pub token: TimeStampToken,
    /// The time-stamping service's certificate, when it was found.
    pub authority: Option<Certificate>,
}
