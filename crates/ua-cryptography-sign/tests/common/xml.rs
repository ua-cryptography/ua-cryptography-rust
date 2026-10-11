//! Reading XML-DSig documents in the tests with `roxmltree` and `ua-cryptography-xml-c14n` alone (the canonicalizer is
//! checked against Microsoft's implementation in its own crate).

use base64::Engine;
use roxmltree::{Document, Node};
use ua_cryptography_xml_c14n::Algorithm;

pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
pub const ASIC: &str = "http://uri.etsi.org/02918/v1.2.1#";
pub const MANIFEST: &str = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

/// The elements named (`namespace`, `name`) in document order.
pub fn elements<'a, 'input>(document: &'a Document<'input>, namespace: &str, name: &str) -> Vec<Node<'a, 'input>> {
    document
        .descendants()
        .filter(|node| node.has_tag_name((namespace, name)))
        .collect()
}

/// The first element named (`namespace`, `name`).
pub fn element<'a, 'input>(document: &'a Document<'input>, namespace: &str, name: &str) -> Node<'a, 'input> {
    elements(document, namespace, name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("no {name}"))
}

/// The first child element named (`namespace`, `name`).
pub fn child<'a, 'input>(node: &Node<'a, 'input>, namespace: &str, name: &str) -> Node<'a, 'input> {
    node.children()
        .find(|child| child.has_tag_name((namespace, name)))
        .unwrap_or_else(|| panic!("no {name}"))
}

/// The element whose Id is `id`.
pub fn by_id<'a, 'input>(document: &'a Document<'input>, id: &str) -> Node<'a, 'input> {
    document
        .descendants()
        .find(|node| node.attribute("Id") == Some(id))
        .unwrap()
}

pub fn text(node: &Node<'_, '_>) -> String {
    node.descendants()
        .filter(Node::is_text)
        .filter_map(|text| text.text())
        .collect::<String>()
        .trim()
        .to_owned()
}

pub fn base64(node: &Node<'_, '_>) -> Vec<u8> {
    let compact: String = text(node).chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(compact).unwrap()
}

/// Exclusive XML canonicalization of an element.
pub fn exclusive(node: Node<'_, '_>) -> Vec<u8> {
    ua_cryptography_xml_c14n::canonicalize(node, Algorithm::Exclusive, &[], None)
}

/// The text of a document with every text node replaced by `*` and every signature id ("S-" and 16 hex digits)
/// replaced by `S-ID`: what is left is the element structure, names, prefixes, attributes and their order.
pub fn skeleton(xml: &str) -> String {
    let mut shape = String::with_capacity(xml.len());
    let mut in_text = false;
    let mut has_text = false;
    for character in xml.chars() {
        match character {
            '<' => {
                if has_text {
                    shape.push('*');
                }
                in_text = false;
                has_text = false;
                shape.push('<');
            }
            '>' => {
                shape.push('>');
                in_text = true;
            }
            _ if in_text => has_text = true,
            _ => shape.push(character),
        }
    }
    replace_ids(&shape)
}

fn replace_ids(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let is_id = bytes[index..].starts_with(b"S-")
            && bytes.len() >= index + 18
            && bytes[index + 2..index + 18].iter().all(|b| b.is_ascii_hexdigit());
        if is_id {
            result.push_str("S-ID");
            index += 18;
        } else {
            let character = text[index..].chars().next().unwrap();
            result.push(character);
            index += character.len_utf8();
        }
    }
    result
}
