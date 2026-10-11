//! The messages of the time-stamp protocol (RFC 3161, 2.4).

use num_bigint::{BigInt, BigUint};
use rand_core::{OsRng, RngCore};
use ua_der::{Asn1Node, tag};

use crate::errors::TimeStampError;
use crate::tsp::TimeStampToken;

/// The media type of a TimeStampReq.
pub const REQUEST_MEDIA_TYPE: &str = "application/timestamp-query";
/// The media type of a TimeStampResp.
pub const RESPONSE_MEDIA_TYPE: &str = "application/timestamp-reply";

/// The TimeStampReq version.
const REQUEST_VERSION: i64 = 1;
/// The bytes of a nonce: 64 bits.
const NONCE_BYTES: usize = 8;
/// PKIStatus granted.
const GRANTED: i32 = 0;
/// PKIStatus grantedWithMods.
const GRANTED_WITH_MODS: i32 = 1;
/// The fields of a TimeStampResp with a token.
const RESPONSE_WITH_TOKEN_FIELDS: usize = 2;

/// A fresh 64-bit nonce for a request, from the OS generator.
pub fn create_nonce() -> BigInt {
    let mut bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    BigInt::from(BigUint::from_bytes_be(&bytes))
}

/// TimeStampReq ::= SEQUENCE { version 1, messageImprint, reqPolicy OPTIONAL, nonce, certReq TRUE }: the service is
/// asked to include its certificate.
pub fn create_request(hash: &[u8], hash_oid: &str, nonce: &BigInt, policy: Option<&str>) -> Vec<u8> {
    let mut fields = vec![
        ua_der::integer_from_i64(REQUEST_VERSION),
        ua_der::sequence([ua_der::algorithm_identifier(hash_oid), ua_der::octet_string(hash)]),
    ];
    if let Some(policy) = policy {
        fields.push(ua_der::object_identifier(policy));
    }
    fields.push(ua_der::integer(nonce));
    fields.push(ua_der::boolean(true));
    ua_der::sequence(fields)
}

/// Parses TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL } and checks that the token
/// answers the request: status granted (0) or grantedWithMods (1), the same imprint and nonce.
pub fn parse_response(
    response: &[u8],
    hash: &[u8],
    hash_oid: &str,
    nonce: &BigInt,
) -> Result<TimeStampToken, TimeStampError> {
    let response = Asn1Node::parse(response)?.expect_tag(tag::SEQUENCE)?;
    let fields = response.children()?;
    let status_info = response.child(0)?;
    let status = status_info.child(0)?.to_i32()?;
    if status != GRANTED && status != GRANTED_WITH_MODS {
        return Err(TimeStampError::Refused {
            status,
            text: status_text(&status_info),
        });
    }
    if fields.len() < RESPONSE_WITH_TOKEN_FIELDS {
        return Err(TimeStampError::NoToken);
    }
    let token = TimeStampToken::load(response.child(1)?.encoded())?;
    if token.imprint_algorithm() != hash_oid || token.imprint() != hash {
        return Err(TimeStampError::OtherImprint);
    }
    if token.nonce() != Some(nonce) {
        return Err(TimeStampError::OtherNonce);
    }
    Ok(token)
}

// PKIStatusInfo.statusString, joined by "; "; empty when absent or unreadable.
fn status_text(status_info: &Asn1Node<'_>) -> String {
    let strings = status_info
        .child(1)
        .ok()
        .filter(|node| node.has_tag(tag::SEQUENCE))
        .and_then(|node| node.children().ok());
    let Some(strings) = strings else {
        return String::new();
    };
    strings
        .iter()
        .filter_map(|text| text.to_text().ok())
        .collect::<Vec<_>>()
        .join("; ")
}
