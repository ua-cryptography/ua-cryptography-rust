use serde_json::Value;
use ua_xml_c14n::Algorithm;
use ua_xml_c14n::DocumentText;
use ua_xml_c14n::roxmltree::Node;

/// The fixture recorded by `tools/csharp-oracle` (generator `c14n-microsoft`).
pub fn read_fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/oracle/c14n-microsoft/c14n-microsoft.json"
    );
    let text = std::fs::read_to_string(path).expect("the c14n-microsoft fixture is present");
    serde_json::from_str(&text).expect("the c14n-microsoft fixture is JSON")
}

pub fn text_of(value: &Value) -> &str {
    value.as_str().expect("a JSON string")
}

pub fn decode(xml: &str) -> DocumentText {
    DocumentText::decode(xml.as_bytes()).expect("the test document decodes")
}

/// The canonical form, as text, of the document (`element` is `None`) or of its `element`-th element in document
/// order.
pub fn canonical_text(xml: &str, element: Option<usize>, algorithm: Algorithm, prefixes: &[&str]) -> String {
    let text = decode(xml);
    let document = text.parse().expect("the test document parses");
    let node = match element {
        Some(index) => element_at(document.root(), index),
        None => document.root(),
    };
    String::from_utf8(ua_xml_c14n::canonicalize(node, algorithm, prefixes, None)).unwrap()
}

/// The `index`-th element in document order.
pub fn element_at<'a, 'input>(root: Node<'a, 'input>, index: usize) -> Node<'a, 'input> {
    root.descendants()
        .filter(Node::is_element)
        .nth(index)
        .expect("the element exists")
}

pub fn algorithm_of(uri: &str) -> Algorithm {
    Algorithm::from_uri(uri).expect("a supported method")
}
