//! The escaping of Canonical XML (C14N 1.0, 2.3): text and attribute values that a parser reads back unchanged.

/// `text` as element content: `&`, `<`, `>` and carriage return escaped.
pub fn escape_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    push_escaped_text(&mut escaped, text);
    escaped
}

/// `value` as a double-quoted attribute value: `&`, `<`, `"`, tab, line feed and carriage return escaped.
pub fn escape_attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    push_escaped_attribute(&mut escaped, value);
    escaped
}

pub(crate) fn push_escaped_text(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\r' => output.push_str("&#xD;"),
            _ => output.push(character),
        }
    }
}

pub(crate) fn push_escaped_attribute(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '"' => output.push_str("&quot;"),
            '\t' => output.push_str("&#x9;"),
            '\n' => output.push_str("&#xA;"),
            '\r' => output.push_str("&#xD;"),
            _ => output.push(character),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_keeps_quotes_and_escapes_markup() {
        assert_eq!(
            escape_text("a & <b> \"q\" 'a'\r\n\t"),
            "a &amp; &lt;b&gt; \"q\" 'a'&#xD;\n\t"
        );
    }

    #[test]
    fn attributes_escape_quotes_and_white_space_but_not_greater_than() {
        assert_eq!(escape_attribute("<&>\"'\t\n\r"), "&lt;&amp;>&quot;'&#x9;&#xA;&#xD;");
    }
}
