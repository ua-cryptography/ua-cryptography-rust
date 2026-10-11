use std::fmt;

use ua_cryptography_der::{Asn1Node, DerError, tag};

use crate::errors::DistinguishedNameError;
use crate::oids;

/// The RFC 4514 keys this crate reads and writes, with their attribute types.
const KEYS: [(&str, &str); 13] = [
    ("CN", oids::COMMON_NAME),
    ("SN", oids::SURNAME),
    ("SERIALNUMBER", oids::SERIAL_NUMBER),
    ("C", oids::COUNTRY),
    ("L", oids::LOCALITY),
    ("ST", oids::STATE),
    ("STREET", oids::STREET),
    ("O", oids::ORGANIZATION),
    ("OU", oids::ORGANIZATIONAL_UNIT),
    ("T", oids::TITLE),
    ("G", oids::GIVEN_NAME),
    ("ORGANIZATIONIDENTIFIER", oids::ORGANIZATION_IDENTIFIER),
    ("E", oids::EMAIL_ADDRESS),
];

/// An X.500 Name (RFC 5280, 4.1.2.4): a sequence of relative distinguished names.
///
/// Two names are equal when their DER encodings are, or else when their attributes match after trimming and ignoring
/// case (RFC 5280, 7.1, simplified).
#[derive(Debug, Clone)]
pub struct DistinguishedName {
    encoded: Vec<u8>,
    attributes: Vec<(String, String)>,
}

impl DistinguishedName {
    /// The DER encoding, exactly as found in the certificate.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// All attributes as (type OID, value) in the order of encoding (one RDN may hold several).
    pub fn attributes(&self) -> &[(String, String)] {
        &self.attributes
    }

    /// The first value of an attribute type, e.g. [`oids::COMMON_NAME`].
    pub fn find_attribute(&self, oid: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(attribute_oid, _)| attribute_oid == oid)
            .map(|(_, value)| value.as_str())
    }

    /// Reads a Name; a value that is not a character string is kept as `#` and the hex of its DER.
    pub fn from_asn1(name: &Asn1Node<'_>) -> Result<Self, DerError> {
        let name = name.expect_tag(tag::SEQUENCE)?;
        let mut attributes = Vec::new();
        for rdn in name.children()? {
            for attribute in rdn.expect_tag(tag::SET)?.children()? {
                let value = attribute.child(1)?;
                let text = match value.to_text() {
                    Ok(text) => text,
                    Err(_) => format!("#{}", hex_upper(value.encoded())),
                };
                attributes.push((attribute.child(0)?.to_oid()?, text));
            }
        }
        Ok(Self {
            encoded: name.encoded().to_vec(),
            attributes,
        })
    }

    /// Parses "CN=Name, O=Organization, C=UA" (RFC 4514 keys plus OIDs; a comma inside a value is written "\,"). The
    /// RDNs are encoded in the order written. C and SERIALNUMBER become PrintableString, E an IA5String, the rest
    /// UTF8String.
    pub fn parse(text: &str) -> Result<Self, DistinguishedNameError> {
        let mut attributes = Vec::new();
        for part in split_unescaped(text) {
            let Some(equals) = part.find('=').filter(|&index| index > 0) else {
                return Err(DistinguishedNameError::InvalidComponent { component: part });
            };
            let key = part[..equals].trim();
            let value = part[equals + 1..].trim();
            attributes.push((attribute_type_of(key)?, value.to_owned()));
        }
        if attributes.is_empty() {
            return Err(DistinguishedNameError::Empty);
        }
        let rdns = attributes.iter().map(|(oid, value)| {
            ua_cryptography_der::set_of([ua_cryptography_der::sequence([
                ua_cryptography_der::object_identifier(oid),
                encode_value(oid, value),
            ])])
        });
        Ok(Self {
            encoded: ua_cryptography_der::sequence(rdns),
            attributes,
        })
    }
}

impl PartialEq for DistinguishedName {
    fn eq(&self, other: &Self) -> bool {
        if self.encoded == other.encoded {
            return true;
        }
        self.attributes.len() == other.attributes.len()
            && self.attributes.iter().zip(&other.attributes).all(|(mine, theirs)| {
                mine.0 == theirs.0 && equal_ignoring_case(&normalize(&mine.1), &normalize(&theirs.1))
            })
    }
}

impl Eq for DistinguishedName {}

impl fmt::Display for DistinguishedName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .attributes
            .iter()
            .map(|(oid, value)| format!("{}={}", key_of(oid), value.replace(',', "\\,")))
            .collect();
        formatter.write_str(&parts.join(", "))
    }
}

fn attribute_type_of(key: &str) -> Result<String, DistinguishedNameError> {
    if let Some((_, oid)) = KEYS.iter().find(|(known, _)| known.eq_ignore_ascii_case(key)) {
        return Ok((*oid).to_owned());
    }
    if key.contains('.') && ua_cryptography_der::encode_oid(key).is_ok() {
        return Ok(key.to_owned());
    }
    Err(DistinguishedNameError::UnknownAttributeType { key: key.to_owned() })
}

fn key_of(oid: &str) -> &str {
    match KEYS.iter().find(|(_, known)| *known == oid) {
        Some((key, _)) => key,
        None => oid,
    }
}

fn encode_value(oid: &str, value: &str) -> Vec<u8> {
    match oid {
        oids::COUNTRY | oids::SERIAL_NUMBER => ua_cryptography_der::printable_string(value),
        oids::EMAIL_ADDRESS => ua_cryptography_der::ia5_string(value),
        _ => ua_cryptography_der::utf8_string(value),
    }
}

// Splits at unescaped ',' and ';'; a backslash takes the next character as it is.
fn split_unescaped(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some(escaped) => current.push(escaped),
                None => current.push('\\'),
            },
            ',' | ';' => parts.push(std::mem::take(&mut current)),
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }
    parts
}

// Runs of spaces become one, leading and trailing spaces go.
fn normalize(value: &str) -> String {
    value
        .split(' ')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn equal_ignoring_case(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_uppercase)
        .eq(b.chars().flat_map(char::to_uppercase))
}

pub(crate) fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_differing_in_case_and_spaces_are_equal() {
        let a = DistinguishedName::parse("CN=Test  Signer, O=UA").unwrap();
        let b = DistinguishedName::parse("CN=test signer,O=ua").unwrap();
        assert_ne!(a.encoded(), b.encoded());
        assert_eq!(a, b);
        assert_ne!(a, DistinguishedName::parse("CN=Test Signer").unwrap());
    }

    #[test]
    fn unknown_keys_and_bare_text_are_refused() {
        assert_eq!(
            DistinguishedName::parse("XX=1"),
            Err(DistinguishedNameError::UnknownAttributeType { key: "XX".to_owned() })
        );
        assert!(matches!(
            DistinguishedName::parse("no equals"),
            Err(DistinguishedNameError::InvalidComponent { .. })
        ));
        assert_eq!(DistinguishedName::parse(""), Err(DistinguishedNameError::Empty));
        let by_oid = DistinguishedName::parse("2.5.4.3=Name").unwrap();
        assert_eq!(by_oid.find_attribute(oids::COMMON_NAME), Some("Name"));
        assert_eq!(by_oid.to_string(), "CN=Name");
    }
}
