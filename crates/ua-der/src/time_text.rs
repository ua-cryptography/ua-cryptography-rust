//! The text forms of UTCTime and GeneralizedTime (X.680, 46–47): reading the forms PKI data uses, writing DER.

use time::Date;
use time::Month;
use time::OffsetDateTime;
use time::PrimitiveDateTime;
use time::Time;
use time::UtcOffset;

use crate::errors::DerError;

/// UTCTime years from 50 are 19YY, below 50 20YY (RFC 5280, 4.1.2.5.1).
const UTC_TIME_PIVOT_YEAR: i32 = 50;
/// The century of UTCTime years at or above the pivot.
const TWENTIETH_CENTURY: i32 = 1900;
/// The century of UTCTime years below the pivot.
const TWENTY_FIRST_CENTURY: i32 = 2000;
/// Years in a century.
const YEARS_PER_CENTURY: i32 = 100;
/// The years a date-time may have.
const MIN_YEAR: i32 = 1;
/// The years a date-time may have.
const MAX_YEAR: i32 = 9999;
/// The length of `+hhmm` / `-hhmm`.
const ZONE_OFFSET_LENGTH: usize = 5;
/// The largest zone offset, in minutes (UTC±14:00).
const MAX_OFFSET_MINUTES: i32 = 14 * 60;
/// Minutes in an hour.
const MINUTES_PER_HOUR: i32 = 60;
/// Seconds in a minute.
const SECONDS_PER_MINUTE: i32 = 60;
/// `YYMMDDhhmmss`.
const UTC_TIME_WITH_SECONDS: usize = 12;
/// `YYMMDDhhmm`.
const UTC_TIME_WITHOUT_SECONDS: usize = 10;
/// `YYYYMMDDhhmmss`.
const GENERALIZED_TIME_WITH_SECONDS: usize = 14;
/// `YYYYMMDDhhmm`.
const GENERALIZED_TIME_WITHOUT_SECONDS: usize = 12;
/// The most fraction digits read (100 ns).
const MAX_FRACTION_DIGITS: usize = 7;
/// The digits of a nanosecond count.
const NANOSECOND_DIGITS: usize = 9;
/// Decimal digits.
const DECIMAL_RADIX: u32 = 10;

/// The calendar fields of a time text, before its zone is applied.
struct TimeFields {
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
}

/// A UTCTime: `YYMMDDhhmm[ss]` with `Z`, `±hhmm` or no zone (read as UTC).
pub(crate) fn parse_utc_time(content: &[u8]) -> Result<OffsetDateTime, DerError> {
    parse_time(content, read_utc_time_fields)
}

/// A GeneralizedTime: `YYYYMMDDhhmm[ss[.f…]]` with `Z`, `±hhmm` or no zone (read as UTC); `,` may stand for `.`.
pub(crate) fn parse_generalized_time(content: &[u8]) -> Result<OffsetDateTime, DerError> {
    parse_time(content, read_generalized_time_fields)
}

/// The DER UTCTime text of `at`: `YYMMDDhhmmssZ`, in UTC, whole seconds.
pub(crate) fn format_utc_time(at: OffsetDateTime) -> String {
    let utc = at.to_offset(UtcOffset::UTC);
    let year = utc.year().rem_euclid(YEARS_PER_CENTURY);
    format!("{year:02}{}Z", format_month_to_second(utc))
}

/// The DER GeneralizedTime text of `at`: `YYYYMMDDhhmmssZ`, in UTC, whole seconds.
///
/// # Panics
/// If the year in UTC is outside 1–9999.
pub(crate) fn format_generalized_time(at: OffsetDateTime) -> String {
    let utc = at.to_offset(UtcOffset::UTC);
    assert!(
        (MIN_YEAR..=MAX_YEAR).contains(&utc.year()),
        "GeneralizedTime years are 1–9999"
    );
    format!("{:04}{}Z", utc.year(), format_month_to_second(utc))
}

fn format_month_to_second(utc: OffsetDateTime) -> String {
    let month = u8::from(utc.month());
    format!(
        "{month:02}{:02}{:02}{:02}{:02}",
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

fn parse_time(content: &[u8], read_fields: fn(&str) -> Option<TimeFields>) -> Result<OffsetDateTime, DerError> {
    let invalid = || DerError::InvalidTime {
        text: String::from_utf8_lossy(content).into_owned(),
    };
    let text = std::str::from_utf8(content)
        .ok()
        .filter(|text| text.is_ascii())
        .ok_or_else(invalid)?;
    let (body, offset_minutes) = split_zone(text).ok_or_else(invalid)?;
    let fields = read_fields(&body.replace(',', ".")).ok_or_else(invalid)?;
    to_utc(&fields, offset_minutes).ok_or_else(invalid)
}

// `Z`, `+hhmm` / `-hhmm`, or nothing; returns the rest and the offset in minutes.
fn split_zone(text: &str) -> Option<(&str, i32)> {
    if let Some(body) = text.strip_suffix('Z') {
        return Some((body, 0));
    }
    if text.len() <= ZONE_OFFSET_LENGTH {
        return Some((text, 0));
    }
    let (body, zone) = text.split_at(text.len() - ZONE_OFFSET_LENGTH);
    let sign = match zone.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return Some((text, 0)),
    };
    let hours = read_number(&zone[1..3])?;
    let minutes = read_number(&zone[3..])?;
    let offset = i32::try_from(hours).ok()? * MINUTES_PER_HOUR + i32::try_from(minutes).ok()?;
    (offset <= MAX_OFFSET_MINUTES).then_some((body, sign * offset))
}

fn read_utc_time_fields(body: &str) -> Option<TimeFields> {
    let has_seconds = match body.len() {
        UTC_TIME_WITH_SECONDS => true,
        UTC_TIME_WITHOUT_SECONDS => false,
        _ => return None,
    };
    let short_year = i32::try_from(read_number(&body[0..2])?).ok()?;
    let century = if short_year >= UTC_TIME_PIVOT_YEAR {
        TWENTIETH_CENTURY
    } else {
        TWENTY_FIRST_CENTURY
    };
    read_month_to_second(century + short_year, &body[2..], has_seconds)
}

fn read_generalized_time_fields(body: &str) -> Option<TimeFields> {
    let (whole, fraction) = match body.split_once('.') {
        Some((whole, fraction)) if whole.len() == GENERALIZED_TIME_WITH_SECONDS => (whole, Some(fraction)),
        Some(_) => return None,
        None => (body, None),
    };
    let has_seconds = match whole.len() {
        GENERALIZED_TIME_WITH_SECONDS => true,
        GENERALIZED_TIME_WITHOUT_SECONDS => false,
        _ => return None,
    };
    let year = i32::try_from(read_number(&whole[0..4])?).ok()?;
    let mut fields = read_month_to_second(year, &whole[4..], has_seconds)?;
    if let Some(fraction) = fraction {
        fields.nanosecond = read_fraction_nanoseconds(fraction)?;
    }
    Some(fields)
}

// `MMDDhhmm[ss]`.
fn read_month_to_second(year: i32, text: &str, has_seconds: bool) -> Option<TimeFields> {
    let field = |start: usize| read_number(&text[start..start + 2]).and_then(|value| u8::try_from(value).ok());
    Some(TimeFields {
        year,
        month: field(0)?,
        day: field(2)?,
        hour: field(4)?,
        minute: field(6)?,
        second: if has_seconds { field(8)? } else { 0 },
        nanosecond: 0,
    })
}

// Up to seven digits, none at all included.
fn read_fraction_nanoseconds(fraction: &str) -> Option<u32> {
    if fraction.len() > MAX_FRACTION_DIGITS || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let padded = format!("{fraction:0<width$}", width = NANOSECOND_DIGITS);
    u32::from_str_radix(&padded, DECIMAL_RADIX).ok()
}

fn read_number(digits: &str) -> Option<u32> {
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    u32::from_str_radix(digits, DECIMAL_RADIX).ok()
}

fn to_utc(fields: &TimeFields, offset_minutes: i32) -> Option<OffsetDateTime> {
    if !(MIN_YEAR..=MAX_YEAR).contains(&fields.year) {
        return None;
    }
    let month = Month::try_from(fields.month).ok()?;
    let date = Date::from_calendar_date(fields.year, month, fields.day).ok()?;
    let time = Time::from_hms_nano(fields.hour, fields.minute, fields.second, fields.nanosecond).ok()?;
    let offset = UtcOffset::from_whole_seconds(offset_minutes * SECONDS_PER_MINUTE).ok()?;
    let utc = PrimitiveDateTime::new(date, time)
        .assume_offset(offset)
        .to_offset(UtcOffset::UTC);
    (MIN_YEAR..=MAX_YEAR).contains(&utc.year()).then_some(utc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn a_utc_time_with_an_offset_keeps_its_century() {
        // 1999-12-31 23:30 at UTC-1 is 2000-01-01 00:30 UTC.
        assert_eq!(
            parse_utc_time(b"991231233000-0100").unwrap(),
            datetime!(2000-01-01 00:30 UTC)
        );
    }

    #[test]
    fn written_times_are_whole_seconds_in_utc() {
        let at = datetime!(2026-10-10 15:34:56.789 +03:00);
        assert_eq!(format_utc_time(at), "261010123456Z");
        assert_eq!(format_generalized_time(at), "20261010123456Z");
        assert_eq!(
            format_generalized_time(datetime!(0999-01-02 03:04:05 UTC)),
            "09990102030405Z"
        );
    }
}
