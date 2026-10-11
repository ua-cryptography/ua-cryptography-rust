//! The canonicalization against Microsoft's (System.Security.Cryptography.Xml, recorded in
//! testdata/oracle/c14n-microsoft): inclusive and exclusive C14N, with and without comments, of whole documents, of
//! element subtrees as same-document references see them, with an InclusiveNamespaces prefix list and with the
//! enveloped-signature transform.

mod common;

use sha2::Digest;
use sha2::Sha256;
use ua_cryptography_xml_c14n::Algorithm;
use ua_cryptography_xml_c14n::DocumentError;
use ua_cryptography_xml_c14n::DocumentText;
use ua_cryptography_xml_c14n::roxmltree::Node;

use common::algorithm_of;
use common::canonical_text;
use common::decode;
use common::element_at;
use common::read_fixture;
use common::text_of;

/// How many documents the C# test runs every theory over.
const TEST_DOCUMENT_COUNT: usize = 9;

#[test]
fn whole_document_matches_microsoft() {
    let fixture = read_fixture();
    let documents = fixture["documents"].as_array().unwrap();
    assert_eq!(documents.len(), TEST_DOCUMENT_COUNT);
    for document in documents {
        let xml = text_of(&document["xml"]);
        let whole = document["whole"].as_object().unwrap();
        assert_eq!(whole.len(), 4);
        for (uri, expected) in whole {
            assert_eq!(
                canonical_text(xml, None, algorithm_of(uri), &[]),
                text_of(expected),
                "{uri} of {xml}"
            );
        }
    }
}

#[test]
fn exclusive_subtree_matches_microsoft() {
    let fixture = read_fixture();
    let mut checked = 0;
    for document in fixture["documents"].as_array().unwrap() {
        let xml = text_of(&document["xml"]);
        for subtree in document["exclusiveSubtrees"].as_array().unwrap() {
            let index = subtree["element"].as_u64().unwrap() as usize;
            let ours = canonical_text(xml, Some(index), Algorithm::Exclusive, &[]);
            assert_eq!(ours, text_of(&subtree["canonical"]), "element {index} of {xml}");
            checked += 1;
        }
    }
    assert!(
        checked >= 25,
        "every element but those with tabs or line ends in attributes"
    );
}

#[test]
fn inclusive_subtree_matches_signed_xml_reference_digest() {
    let fixture = read_fixture();
    let mut checked = 0;
    for document in fixture["documents"].as_array().unwrap() {
        let target = &document["target"];
        if target.is_null() {
            continue;
        }
        let xml = text_of(&document["xml"]);
        let text = decode(xml);
        let parsed = text.parse().unwrap();
        let element = parsed
            .descendants()
            .find(|node| node.attribute("Id") == Some("target"))
            .unwrap();
        assert_eq!(
            Some(element),
            Some(element_at(parsed.root(), target["element"].as_u64().unwrap() as usize))
        );

        let ours = ua_cryptography_xml_c14n::canonicalize(element, Algorithm::Inclusive, &[], None);
        assert_eq!(
            to_hex(&Sha256::digest(&ours)),
            text_of(&target["sha256"]),
            "digest of #target in {xml}"
        );
        assert_eq!(String::from_utf8(ours).unwrap(), text_of(&target["canonical"]));
        checked += 1;
    }
    assert_eq!(checked, 5);
}

#[test]
fn inclusive_namespaces_prefix_list_matches_microsoft() {
    let fixture = read_fixture();
    let prefix_lists = &fixture["prefixLists"];
    let xml = text_of(&prefix_lists["xml"]);
    let cases = prefix_lists["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let list = text_of(&case["prefixList"]);
        let prefixes: Vec<&str> = list.split(' ').collect();
        assert_eq!(
            canonical_text(xml, None, Algorithm::Exclusive, &prefixes),
            text_of(&case["canonical"]),
            "{list}"
        );
    }
}

#[test]
fn enveloped_signature_transform_leaves_the_signature_out() {
    let fixture = read_fixture();
    let enveloped = &fixture["enveloped"];
    let text = decode(text_of(&enveloped["xml"]));
    let document = text.parse().unwrap();
    let signature = document
        .descendants()
        .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "Signature")))
        .unwrap();
    let ours = ua_cryptography_xml_c14n::canonicalize(document.root(), Algorithm::Inclusive, &[], Some(signature));
    assert_eq!(String::from_utf8(ours).unwrap(), text_of(&enveloped["canonical"]));
}

#[test]
fn xades_builder_document_matches_microsoft() {
    let fixture = read_fixture();
    let xades = &fixture["xades"];
    let xml = text_of(&xades["xml"]);
    let text = decode(xml);
    let document = text.parse().unwrap();
    let elements: Vec<Node> = document.descendants().filter(Node::is_element).collect();
    let subtrees = xades["exclusiveSubtrees"].as_array().unwrap();
    assert_eq!(subtrees.len(), elements.len());
    for subtree in subtrees {
        let index = subtree["element"].as_u64().unwrap() as usize;
        let ours = ua_cryptography_xml_c14n::canonicalize(elements[index], Algorithm::Exclusive, &[], None);
        assert_eq!(
            String::from_utf8(ours).unwrap(),
            text_of(&subtree["canonical"]),
            "element {index}"
        );
    }
    let ours = ua_cryptography_xml_c14n::canonicalize(document.root(), Algorithm::Inclusive, &[], None);
    assert_eq!(String::from_utf8(ours).unwrap(), text_of(&xades["inclusiveDocument"]));
}

#[test]
fn document_type_definitions_are_refused() {
    let xxe = r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>"#;
    let text = DocumentText::decode(xxe.as_bytes()).unwrap();
    assert_eq!(text.parse().err(), Some(DocumentError::DtdRefused));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}
