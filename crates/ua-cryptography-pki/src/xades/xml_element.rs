//! XML built as a tree and written as text the way .NET's XmlWriter writes an XmlDocument: attributes in the order
//! set, namespace declarations as attributes where they are put, an empty element as `<name />`.

use ua_cryptography_xml_c14n::{escape_attribute, escape_text};

/// One element with its attributes and content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XmlElement {
    name: String,
    attributes: Vec<(String, String)>,
    children: Vec<XmlContent>,
}

/// The content of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XmlContent {
    Element(XmlElement),
    Text(String),
}

impl XmlElement {
    /// An element named `name` (with its prefix, e.g. "ds:Signature").
    pub(crate) fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// The element with one more attribute.
    pub(crate) fn with_attribute(mut self, name: &str, value: &str) -> Self {
        self.attributes.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The element with one more child element.
    pub(crate) fn with_child(mut self, child: XmlElement) -> Self {
        self.children.push(XmlContent::Element(child));
        self
    }

    /// The element with text content.
    pub(crate) fn with_text(mut self, text: &str) -> Self {
        self.children.push(XmlContent::Text(text.to_owned()));
        self
    }

    /// The same element without the attribute `name` (a namespace declaration a new ancestor takes over).
    pub(crate) fn without_attribute(&self, name: &str) -> Self {
        let mut element = self.clone();
        element.attributes.retain(|(attribute, _)| attribute != name);
        element
    }

    /// The element as text.
    pub(crate) fn to_text(&self) -> String {
        let mut text = String::new();
        self.write(&mut text);
        text
    }

    /// Appends the element as text.
    pub(crate) fn write(&self, output: &mut String) {
        output.push('<');
        output.push_str(&self.name);
        for (name, value) in &self.attributes {
            output.push(' ');
            output.push_str(name);
            output.push_str("=\"");
            output.push_str(&escape_attribute(value));
            output.push('"');
        }
        if self.children.is_empty() {
            output.push_str(" />");
            return;
        }
        output.push('>');
        for child in &self.children {
            match child {
                XmlContent::Element(element) => element.write(output),
                XmlContent::Text(text) => output.push_str(&escape_text(text)),
            }
        }
        output.push_str("</");
        output.push_str(&self.name);
        output.push('>');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elements_are_written_as_dotnet_writes_them() {
        let element = XmlElement::new("ds:Reference")
            .with_attribute("URI", "a&b")
            .with_child(XmlElement::new("ds:DigestMethod").with_attribute("Algorithm", "x"))
            .with_child(XmlElement::new("ds:DigestValue").with_text("<=>"));
        assert_eq!(
            element.to_text(),
            "<ds:Reference URI=\"a&amp;b\"><ds:DigestMethod Algorithm=\"x\" /><ds:DigestValue>&lt;=&gt;</ds:DigestValue></ds:Reference>"
        );
        assert_eq!(element.without_attribute("URI").to_text().find("URI"), None);
    }
}
