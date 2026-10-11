use std::fmt;

use ua_der::DerError;

use crate::errors::CmsError;

/// Why a time-stamp token or a time-stamp response (RFC 3161) is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeStampError {
    /// The token is not a readable CMS SignedData.
    Cms(CmsError),
    /// The TSTInfo or the response is not the DER expected.
    Der(DerError),
    /// The token does not encapsulate a TSTInfo.
    NotTstInfo,
    /// The token does not have exactly one signer.
    SignerCount {
        /// How many signers it has.
        count: usize,
    },
    /// The service answered with a status other than granted (0) or grantedWithMods (1).
    Refused {
        /// The PKIStatus.
        status: i32,
        /// The status strings, joined by "; ".
        text: String,
    },
    /// The response has no token.
    NoToken,
    /// The token's message imprint is not the hash asked for.
    OtherImprint,
    /// The token's nonce is not the one sent.
    OtherNonce,
}

impl fmt::Display for TimeStampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cms(error) => write!(formatter, "{error}"),
            Self::Der(error) => write!(formatter, "Invalid time-stamp structure: {error}."),
            Self::NotTstInfo => write!(formatter, "The token does not encapsulate a TSTInfo."),
            Self::SignerCount { .. } => write!(formatter, "A time-stamp token must have exactly one signer."),
            Self::Refused { status, text } => {
                let refusal = format!("The time-stamping service refused the request (status {status}) {text}");
                write!(formatter, "{}", refusal.trim())
            }
            Self::NoToken => write!(formatter, "The time-stamp response has no token."),
            Self::OtherImprint => write!(formatter, "The time-stamp token covers other data than requested."),
            Self::OtherNonce => write!(formatter, "The time-stamp token has a different nonce than requested."),
        }
    }
}

impl std::error::Error for TimeStampError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cms(error) => Some(error),
            Self::Der(error) => Some(error),
            _ => None,
        }
    }
}

impl From<DerError> for TimeStampError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl From<CmsError> for TimeStampError {
    fn from(error: CmsError) -> Self {
        Self::Cms(error)
    }
}
