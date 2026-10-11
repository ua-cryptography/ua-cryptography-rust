//! The text of the JSON reports: times, serial numbers, digests and algorithm names as `ua-sign` writes them.

use num_bigint::BigInt;
use serde::Serialize;
use time::{OffsetDateTime, UtcOffset};
use ua_cryptography_pki::algorithms;

use crate::models::reports::AlgorithmRow;

/// The radix of serial numbers.
const HEX_RADIX: u32 = 16;

/// yyyy-MM-ddTHH:mm:ssZ.
pub fn format_time(time: OffsetDateTime) -> String {
    let utc = time.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// Upper-case hex without leading zeros.
pub fn format_serial(serial: &BigInt) -> String {
    serial.to_str_radix(HEX_RADIX).to_uppercase()
}

/// Upper-case hex.
pub fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// A hash by its identifier, with its readable name.
pub fn describe_hash(identifier: &str) -> AlgorithmRow {
    AlgorithmRow {
        identifier: identifier.to_owned(),
        name: algorithms::hash_name(identifier).to_owned(),
    }
}

/// A signature algorithm by its identifier, with its readable name.
pub fn describe_signature_algorithm(identifier: &str) -> AlgorithmRow {
    AlgorithmRow {
        identifier: identifier.to_owned(),
        name: algorithms::signature_algorithm_name(identifier).to_owned(),
    }
}

/// The UTF-8 JSON of a report.
pub fn to_json<T: Serialize>(report: &T) -> Vec<u8> {
    match serde_json::to_vec(report) {
        Ok(json) => json,
        // The reports hold strings, numbers, booleans and lists only.
        Err(error) => unreachable!("a report always serializes: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_utc_in_iso_8601() {
        let time = time::macros::datetime!(2026-01-01 14:00:25 +02:00);
        assert_eq!(format_time(time), "2026-01-01T12:00:25Z");
    }

    #[test]
    fn serial_numbers_and_digests_are_upper_case_hex() {
        assert_eq!(format_serial(&BigInt::from(0x0A_FF)), "AFF");
        assert_eq!(format_hex(&[0x0A, 0xFF]), "0AFF");
    }
}
