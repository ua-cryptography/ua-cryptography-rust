//! Times as the reports and XAdES write them, always in UTC.

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

/// "yyyy-MM-dd".
pub(crate) fn format_date(time: OffsetDateTime) -> String {
    let time = time.to_offset(UtcOffset::UTC);
    format!("{:04}-{:02}-{:02}", time.year(), u8::from(time.month()), time.day())
}

/// "yyyy-MM-dd HH:mm".
pub(crate) fn format_minutes(time: OffsetDateTime) -> String {
    let utc = time.to_offset(UtcOffset::UTC);
    format!("{} {:02}:{:02}", format_date(utc), utc.hour(), utc.minute())
}

/// "yyyy-MM-dd HH:mm:ss".
pub(crate) fn format_seconds(time: OffsetDateTime) -> String {
    let utc = time.to_offset(UtcOffset::UTC);
    format!("{}:{:02}", format_minutes(utc), utc.second())
}

/// xs:dateTime in UTC with whole seconds, "yyyy-MM-ddTHH:mm:ssZ", as "Дія" and IIT write xades:SigningTime.
pub(crate) fn format_xml_seconds(time: OffsetDateTime) -> String {
    let utc = time.to_offset(UtcOffset::UTC);
    format!(
        "{}T{:02}:{:02}:{:02}Z",
        format_date(utc),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// An xs:dateTime: with a zone ("Z", "+03:00") as RFC 3339 reads it; without one it is taken as UTC.
pub(crate) fn parse_xml_date_time(text: &str) -> Option<OffsetDateTime> {
    if let Ok(time) = OffsetDateTime::parse(text, &Rfc3339) {
        return Some(time.to_offset(UtcOffset::UTC));
    }
    OffsetDateTime::parse(&format!("{text}Z"), &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn times_are_written_in_utc() {
        let time = datetime!(2026-10-10 21:05:09 +3);
        assert_eq!(format_seconds(time), "2026-10-10 18:05:09");
        assert_eq!(format_minutes(time), "2026-10-10 18:05");
        assert_eq!(format_xml_seconds(time), "2026-10-10T18:05:09Z");
    }

    #[test]
    fn xml_times_with_and_without_a_zone_are_read() {
        assert_eq!(
            parse_xml_date_time("2026-10-10T21:05:09+03:00"),
            Some(datetime!(2026-10-10 18:05:09 UTC))
        );
        assert_eq!(
            parse_xml_date_time("2026-10-10T18:05:09.5Z"),
            Some(datetime!(2026-10-10 18:05:09.5 UTC))
        );
        assert_eq!(
            parse_xml_date_time("2026-10-10T18:05:09"),
            Some(datetime!(2026-10-10 18:05:09 UTC))
        );
        assert_eq!(parse_xml_date_time("yesterday"), None);
    }
}
