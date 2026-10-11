//! Every element subtree of the test documents and of documents that probe the parser (line ends, processing
//! instructions, attribute order, odd white space in tags) against the reference implementation's canonicalizer, as
//! recorded in testdata/oracle/c14n-microsoft; and the crate's other functions.

mod common;

use ua_cryptography_xml_c14n::Algorithm;
use ua_cryptography_xml_c14n::DocumentError;
use ua_cryptography_xml_c14n::DocumentText;

use common::algorithm_of;
use common::canonical_text;
use common::read_fixture;
use common::text_of;

#[test]
fn every_subtree_with_every_method_matches_the_reference() {
    let fixture = read_fixture();
    let documents = fixture["reference"].as_array().unwrap();
    let mut checked = 0;
    for document in documents {
        let xml = text_of(&document["xml"]);
        for case in document["cases"].as_array().unwrap() {
            let element = case["element"].as_u64().map(|index| index as usize);
            let algorithm = algorithm_of(text_of(&case["algorithm"]));
            let ours = canonical_text(xml, element, algorithm, &[]);
            assert_eq!(
                ours,
                text_of(&case["canonical"]),
                "{algorithm:?} of element {element:?} in {xml:?}"
            );
            checked += 1;
        }
    }
    assert!(checked > 200);
}

#[test]
fn nesting_deeper_than_sixty_four_levels_is_refused() {
    let nested = |depth: usize| format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));
    let deepest_accepted = nested(64);
    assert_eq!(
        canonical_text(&deepest_accepted, None, Algorithm::Exclusive, &[]),
        deepest_accepted
    );
    let too_deep = DocumentText::decode(nested(65).as_bytes()).unwrap();
    assert_eq!(too_deep.parse().err(), Some(DocumentError::TooDeep));
    let hostile = DocumentText::decode(nested(1_000_000).as_bytes()).unwrap();
    assert_eq!(hostile.parse().err(), Some(DocumentError::TooDeep));
}

#[test]
fn escaped_text_and_attributes_parse_back_unchanged() {
    let text = "a & <b> \"c\" \r\n\t ]]>";
    let value = "x\t\"y\"\n<&>\r";
    let xml = format!(
        "<r a=\"{}\">{}</r>",
        ua_cryptography_xml_c14n::escape_attribute(value),
        ua_cryptography_xml_c14n::escape_text(text)
    );
    let decoded = DocumentText::decode(xml.as_bytes()).unwrap();
    let document = decoded.parse().unwrap();
    let root = document.root_element();
    assert_eq!(root.attribute("a"), Some(value));
    assert_eq!(root.text(), Some(text));
}

#[test]
fn xml_is_recognised_after_a_byte_order_mark_and_white_space() {
    assert!(ua_cryptography_xml_c14n::looks_like_xml(b"<r/>"));
    assert!(ua_cryptography_xml_c14n::looks_like_xml(
        b"\xEF\xBB\xBF \r\n\t<?xml version=\"1.0\"?><r/>"
    ));
    assert!(!ua_cryptography_xml_c14n::looks_like_xml(b"0\x82\x01"));
    assert!(!ua_cryptography_xml_c14n::looks_like_xml(b" \n"));
    assert!(!ua_cryptography_xml_c14n::looks_like_xml(b""));
}

#[test]
fn malformed_xml_is_refused() {
    let text = DocumentText::decode(b"<r><s></r>").unwrap();
    assert!(matches!(text.parse(), Err(DocumentError::Malformed { .. })));
    let unbound = DocumentText::decode(b"<p:r/>").unwrap();
    assert!(matches!(unbound.parse(), Err(DocumentError::Malformed { .. })));
}

#[test]
fn the_excluded_node_may_be_any_child() {
    let text = DocumentText::decode(b"<r><!--c--><s/>t</r>").unwrap();
    let document = text.parse().unwrap();
    let comment = document.descendants().find(|node| node.is_comment()).unwrap();
    let canonical =
        ua_cryptography_xml_c14n::canonicalize(document.root(), Algorithm::InclusiveWithComments, &[], Some(comment));
    assert_eq!(canonical, b"<r><s></s>t</r>");
}

#[test]
#[should_panic(expected = "only a document or an element")]
fn canonicalizing_a_text_node_is_a_bug() {
    let text = DocumentText::decode(b"<r>t</r>").unwrap();
    let document = text.parse().unwrap();
    let text_node = document.root_element().first_child().unwrap();
    ua_cryptography_xml_c14n::canonicalize(text_node, Algorithm::Inclusive, &[], None);
}
