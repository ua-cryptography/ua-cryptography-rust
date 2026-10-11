use crate::xades::xml_element::XmlElement;

/// The XML declaration .NET's XmlWriter writes for a UTF-8 document.
pub(crate) const XML_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
/// The namespace declaration of the `ds` prefix on ds:Signature.
pub(crate) const DS_DECLARATION: &str = "xmlns:ds";

/// A detached XAdES signature as [`XadesSigner`](crate::XadesSigner) makes it: one ds:Signature element, written as a
/// standalone document by [`to_bytes`](Self::to_bytes) or wrapped into an ASiC-E container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XadesSignature {
    id: String,
    element: XmlElement,
}

impl XadesSignature {
    pub(crate) fn new(id: String, element: XmlElement) -> Self {
        Self { id, element }
    }

    /// The Id of ds:Signature, "S-" and 16 hex digits.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The signature as a UTF-8 XML document with an XML declaration, not indented.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut text = String::from(XML_DECLARATION);
        self.element.write(&mut text);
        text.into_bytes()
    }

    /// The ds:Signature element without its `xmlns:ds` declaration, for a parent that declares the prefix.
    pub(crate) fn element_inside_ds_scope(&self) -> XmlElement {
        self.element.without_attribute(DS_DECLARATION)
    }
}
