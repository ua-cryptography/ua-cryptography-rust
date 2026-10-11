//! Reference URIs of file names: percent-encoding as RFC 3986 data (everything but the unreserved characters) with
//! '/' kept, and its reverse.

/// The escape character.
const PERCENT: u8 = b'%';
/// The digits of an escape.
const ESCAPE_DIGITS: usize = 2;
/// The radix of an escape.
const HEX_RADIX: u32 = 16;

/// The URI of a file name: UTF-8 bytes other than `A–Z a–z 0–9 - _ . ~ /` written as %XX.
pub(crate) fn escape_file_name(name: &str) -> String {
    let mut escaped = String::with_capacity(name.len());
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

/// The text of a URI with its %XX escapes decoded; a URI whose escapes are not UTF-8 is returned as it is.
pub(crate) fn unescape(uri: &str) -> String {
    let bytes = uri.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escape = bytes.get(index + 1..index + 1 + ESCAPE_DIGITS).and_then(|digits| {
            let digits = std::str::from_utf8(digits).ok()?;
            u8::from_str_radix(digits, HEX_RADIX).ok()
        });
        match escape {
            Some(byte) if bytes[index] == PERCENT => {
                decoded.push(byte);
                index += 1 + ESCAPE_DIGITS;
            }
            _ => {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
    }
    match String::from_utf8(decoded) {
        Ok(text) => text,
        Err(_) => uri.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_round_trip_through_their_uris() {
        assert_eq!(escape_file_name("data file.bin"), "data%20file.bin");
        assert_eq!(escape_file_name("заява.txt"), "%D0%B7%D0%B0%D1%8F%D0%B2%D0%B0.txt");
        assert_eq!(escape_file_name("annex/табл.csv"), "annex/%D1%82%D0%B0%D0%B1%D0%BB.csv");
        for name in ["data file.bin", "заява.txt", "a+b&c=%d"] {
            assert_eq!(unescape(&escape_file_name(name)), name);
        }
        assert_eq!(unescape("100%"), "100%");
        assert_eq!(unescape("%FF"), "%FF");
    }
}
