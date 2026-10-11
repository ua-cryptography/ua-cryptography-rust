use serde_json::Value;

/// The fixture recorded by `tools/csharp-oracle` (generator `der-bc`).
pub fn read_fixture() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/oracle/der-bc/der-bc.json");
    let text = std::fs::read_to_string(path).expect("the der-bc fixture is present");
    serde_json::from_str(&text).expect("the der-bc fixture is JSON")
}

pub fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

pub fn text_of(value: &Value) -> &str {
    value.as_str().expect("a JSON string")
}
