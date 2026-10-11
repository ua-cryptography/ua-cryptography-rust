//! PEM (RFC 7468): DER, PEM text or bare base64 text in, DER out; DER in, PEM text out.

use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::GeneralPurpose;
use base64::engine::GeneralPurposeConfig;

use crate::errors::PemError;
use crate::tag;

/// Base64 characters per line of PEM text (RFC 7468 allows up to 76, as MIME writes).
const BASE64_LINE_LENGTH: usize = 76;
/// What a byte outside ASCII becomes when the data is read as text.
const ASCII_REPLACEMENT: char = '?';

/// Padding required, non-zero trailing bits tolerated, as a lenient base64 reader does.
const LENIENT_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// The DER bytes of `data`: DER itself (a SEQUENCE), a PEM block labelled `label`, or bare base64 text.
///
/// Text outside the block and whitespace inside it are ignored; an empty text is empty DER.
pub fn decode_pem(data: &[u8], label: &str) -> Result<Vec<u8>, PemError> {
    if data.first() == Some(&tag::SEQUENCE) {
        return Ok(data.to_vec());
    }
    let text: String = data
        .iter()
        .map(|&byte| {
            if byte.is_ascii() {
                char::from(byte)
            } else {
                ASCII_REPLACEMENT
            }
        })
        .collect();
    let text = text.trim_matches(is_whitespace);
    let body = block_body(text, label)?;
    let base64: String = body.chars().filter(|&character| !is_whitespace(character)).collect();
    LENIENT_BASE64.decode(base64).map_err(|_| PemError::NotBase64 {
        label: label.to_owned(),
    })
}

/// PEM text of `der` labelled `label`: base64 in lines of 76 characters, `\n` line ends.
pub fn encode_pem(der: &[u8], label: &str) -> String {
    let base64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = (0..base64.len())
        .step_by(BASE64_LINE_LENGTH)
        .map(|start| &base64[start..base64.len().min(start + BASE64_LINE_LENGTH)])
        .collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

// The text between the markers when a BEGIN marker is present, else the whole text.
fn block_body<'a>(text: &'a str, label: &str) -> Result<&'a str, PemError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let Some(start) = text.find(&begin) else {
        return Ok(text);
    };
    let body = &text[start + begin.len()..];
    match body.find(&end) {
        Some(stop) => Ok(&body[..stop]),
        None => Err(PemError::Unterminated {
            label: label.to_owned(),
        }),
    }
}

// ASCII white space, vertical tab included.
fn is_whitespace(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\u{0B}' | '\u{0C}' | '\r' | ' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_der_breaks_into_lines_of_seventy_six() {
        let der: Vec<u8> = (0..120).collect();
        let pem = encode_pem(&der, "X");
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[1].len(), BASE64_LINE_LENGTH);
        assert_eq!(lines[3], "cnN0dXZ3");
        assert_eq!(decode_pem(pem.as_bytes(), "X").unwrap(), der);
    }

    #[test]
    fn non_canonical_trailing_bits_are_tolerated() {
        assert_eq!(decode_pem(b"QR==", "X").unwrap(), [0x41]);
    }

    #[test]
    fn missing_padding_is_refused() {
        assert_eq!(
            decode_pem(b"QQ", "X"),
            Err(PemError::NotBase64 { label: "X".to_owned() })
        );
    }

    #[test]
    fn an_unterminated_block_is_refused() {
        let pem = b"-----BEGIN X-----\nAAAA\n";
        assert_eq!(
            decode_pem(pem, "X"),
            Err(PemError::Unterminated { label: "X".to_owned() })
        );
    }

    #[test]
    fn an_empty_text_is_empty_der() {
        assert_eq!(decode_pem(b" \n", "X").unwrap(), Vec::<u8>::new());
    }
}
