use roxmltree::Document;
use roxmltree::ParsingOptions;

use crate::document_error::DocumentError;

/// The UTF-8 byte order mark.
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
/// The UTF-16 little-endian byte order mark.
const UTF16_LE_BOM: [u8; 2] = [0xFF, 0xFE];
/// The UTF-16 big-endian byte order mark.
const UTF16_BE_BOM: [u8; 2] = [0xFE, 0xFF];
/// The octets of one UTF-16 code unit.
const UTF16_UNIT_LENGTH: usize = 2;
/// The byte order mark as a character.
const BOM_CHARACTER: char = '\u{FEFF}';
/// How an XML declaration starts.
const DECLARATION_START: &str = "<?xml";
/// How an XML declaration ends.
const DECLARATION_END: &str = "?>";
/// The pseudo-attribute that names the encoding.
const ENCODING_PSEUDO_ATTRIBUTE: &str = "encoding";
/// The deepest element nesting parsed; the parser recurses per level and must not exhaust a thread's stack.
const MAX_NESTING_DEPTH: usize = 64;
/// Encodings whose text is decoded here; any other is read only when the text is plain ASCII.
const DECODED_ENCODINGS: [&str; 5] = ["utf-8", "utf8", "utf-16", "utf-16le", "utf-16be"];

/// The text of an XML document ready for parsing: decoded to UTF-8, line ends normalized (XML 1.0, 2.11).
///
/// Parsing borrows the text, so a document is read in two steps:
/// `let text = DocumentText::decode(&bytes)?; let document = text.parse()?;`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentText {
    text: String,
}

impl DocumentText {
    /// Decodes UTF-8 (with or without a byte order mark) or UTF-16 (with one) and turns `\r\n` and `\r` into `\n`.
    pub fn decode(data: &[u8]) -> Result<Self, DocumentError> {
        let text = decode_unicode(data)?;
        check_declared_encoding(&text)?;
        Ok(DocumentText {
            text: normalize_line_ends(&text),
        })
    }

    /// Parses the text: whitespace, comments and processing instructions kept, DTDs refused, elements nested
    /// deeper than 64 levels refused (the parser recurses per level).
    pub fn parse(&self) -> Result<Document<'_>, DocumentError> {
        if exceeds_nesting_depth(&self.text, MAX_NESTING_DEPTH) {
            return Err(DocumentError::TooDeep);
        }
        let options = ParsingOptions {
            allow_dtd: false,
            ..ParsingOptions::default()
        };
        Document::parse_with_options(&self.text, options).map_err(|error| match error {
            roxmltree::Error::DtdDetected => DocumentError::DtdRefused,
            other => DocumentError::Malformed {
                message: other.to_string(),
            },
        })
    }

    /// The decoded, normalized text.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// True when the data looks like XML: `<` after an optional UTF-8 byte order mark and white space.
pub fn looks_like_xml(data: &[u8]) -> bool {
    let data = data.strip_prefix(&UTF8_BOM).unwrap_or(data);
    data.iter().find(|&&byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n')) == Some(&b'<')
}

fn decode_unicode(data: &[u8]) -> Result<String, DocumentError> {
    if let Some(rest) = data.strip_prefix(&UTF16_LE_BOM) {
        return decode_utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = data.strip_prefix(&UTF16_BE_BOM) {
        return decode_utf16(rest, u16::from_be_bytes);
    }
    let rest = data.strip_prefix(&UTF8_BOM).unwrap_or(data);
    String::from_utf8(rest.to_vec()).map_err(|_| DocumentError::InvalidUtf8)
}

fn decode_utf16(data: &[u8], unit_of: fn([u8; 2]) -> u16) -> Result<String, DocumentError> {
    let chunks = data.chunks_exact(UTF16_UNIT_LENGTH);
    if !chunks.remainder().is_empty() {
        return Err(DocumentError::InvalidUtf16);
    }
    let units = chunks.map(|pair| unit_of([pair[0], pair[1]]));
    let text: String = char::decode_utf16(units)
        .collect::<Result<_, _>>()
        .map_err(|_| DocumentError::InvalidUtf16)?;
    Ok(text.strip_prefix(BOM_CHARACTER).map(str::to_owned).unwrap_or(text))
}

// Without a decoder for it, a declared single-byte encoding is honoured only where it agrees with ASCII.
fn check_declared_encoding(text: &str) -> Result<(), DocumentError> {
    let Some(name) = find_declared_encoding(text) else {
        return Ok(());
    };
    let is_decoded = DECODED_ENCODINGS
        .iter()
        .any(|decoded| decoded.eq_ignore_ascii_case(name));
    if is_decoded || text.is_ascii() {
        return Ok(());
    }
    Err(DocumentError::UnsupportedEncoding { name: name.to_owned() })
}

// The value of `encoding="…"` in the XML declaration, if there is one.
fn find_declared_encoding(text: &str) -> Option<&str> {
    let declaration = text.strip_prefix(DECLARATION_START)?;
    let declaration = &declaration[..declaration.find(DECLARATION_END)?];
    let after_name = &declaration[declaration.find(ENCODING_PSEUDO_ATTRIBUTE)? + ENCODING_PSEUDO_ATTRIBUTE.len()..];
    let after_equals = after_name.trim_start().strip_prefix('=')?.trim_start();
    let quote = after_equals
        .chars()
        .next()
        .filter(|&quote| quote == '"' || quote == '\'')?;
    let value = &after_equals[quote.len_utf8()..];
    Some(&value[..value.find(quote)?])
}

// A light scan of the markup: comments, CDATA sections, PIs, declarations and quoted attribute values are skipped,
// so only tags count; the parser checks well-formedness afterwards.
fn exceeds_nesting_depth(text: &str, max_depth: usize) -> bool {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut position = 0;
    while let Some(offset) = bytes[position..].iter().position(|&byte| byte == b'<') {
        let tag = &bytes[position + offset..];
        let (length, step) = measure_markup(tag);
        match step {
            DepthStep::Open => depth += 1,
            DepthStep::Close => depth = depth.saturating_sub(1),
            DepthStep::Same => {}
        }
        if depth > max_depth {
            return true;
        }
        position += offset + length;
    }
    false
}

/// What one piece of markup does to the nesting depth.
enum DepthStep {
    Open,
    Close,
    Same,
}

// The length of the markup that starts at `markup[0] == b'<'`, and what it does to the depth.
fn measure_markup(markup: &[u8]) -> (usize, DepthStep) {
    let skipped = [("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>"), ("<!", ">")];
    for (start, end) in skipped {
        if markup.starts_with(start.as_bytes()) {
            return (length_through(markup, start.len(), end), DepthStep::Same);
        }
    }
    if markup.starts_with(b"</") {
        return (length_through(markup, 2, ">"), DepthStep::Close);
    }
    let mut quote = None;
    for (index, &byte) in markup.iter().enumerate().skip(1) {
        match (quote, byte) {
            (Some(open), _) if byte == open => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(byte),
            (None, b'>') if markup[index - 1] == b'/' => return (index + 1, DepthStep::Same),
            (None, b'>') => return (index + 1, DepthStep::Open),
            (None, _) => {}
        }
    }
    (markup.len(), DepthStep::Same)
}

// The length up to and including `end`, searched from `from`; the rest of the text when there is no `end`.
fn length_through(markup: &[u8], from: usize, end: &str) -> usize {
    let end = end.as_bytes();
    match markup[from..].windows(end.len()).position(|window| window == end) {
        Some(index) => from + index + end.len(),
        None => markup.len(),
    }
}

// XML 1.0, 2.11: `\r\n` and a lone `\r` become `\n` before parsing.
fn normalize_line_ends(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_with_a_byte_order_mark_is_decoded() {
        let mut data = vec![0xFF, 0xFE];
        data.extend("<r>Ж</r>".encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(DocumentText::decode(&data).unwrap().as_str(), "<r>Ж</r>");
        let mut data = vec![0xFE, 0xFF];
        data.extend("<r/>".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(DocumentText::decode(&data).unwrap().as_str(), "<r/>");
    }

    #[test]
    fn invalid_unicode_is_refused() {
        assert_eq!(DocumentText::decode(b"<r>\xFF</r>"), Err(DocumentError::InvalidUtf8));
        assert_eq!(
            DocumentText::decode(&[0xFF, 0xFE, 0x3C]),
            Err(DocumentError::InvalidUtf16)
        );
        assert_eq!(
            DocumentText::decode(&[0xFF, 0xFE, 0x00, 0xD8]),
            Err(DocumentError::InvalidUtf16)
        );
    }

    #[test]
    fn a_single_byte_encoding_is_read_only_as_ascii() {
        let ascii = b"<?xml version='1.0' encoding='windows-1251'?><r/>";
        assert!(DocumentText::decode(ascii).is_ok());
        let cyrillic = "<?xml version=\"1.0\" encoding = \"windows-1251\"?><r>Ж</r>";
        let refusal = DocumentError::UnsupportedEncoding {
            name: "windows-1251".to_owned(),
        };
        assert_eq!(DocumentText::decode(cyrillic.as_bytes()), Err(refusal));
        assert!(DocumentText::decode("<?xml version=\"1.0\" encoding=\"UTF-8\"?><r>Ж</r>".as_bytes()).is_ok());
    }

    #[test]
    fn only_tags_count_towards_the_nesting_depth() {
        assert!(!exceeds_nesting_depth(
            "<a><b/><c x='/>' y=\"<\"><!--<d>--><![CDATA[<e>]]><?p <f>?></c></a>",
            2
        ));
        assert!(exceeds_nesting_depth("<a><b><c/></b></a>", 1));
        assert!(!exceeds_nesting_depth("<a></a><b></b>", 1));
    }

    #[test]
    fn line_ends_are_normalized_before_parsing() {
        assert_eq!(normalize_line_ends("a\r\nb\rc\n\r\r\n"), "a\nb\nc\n\n\n");
    }
}
