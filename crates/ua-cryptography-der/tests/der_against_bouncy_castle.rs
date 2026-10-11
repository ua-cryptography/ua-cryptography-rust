//! The DER writer and reader against BouncyCastle's encodings (recorded in testdata/oracle/der-bc): the same bytes for
//! every primitive and for SET OF ordering, BER forms accepted on input, and malformed input refused.

mod common;

use std::str::FromStr;

use num_bigint::BigInt;
use time::macros::datetime;
use ua_cryptography_der::Asn1Node;
use ua_cryptography_der::DerError;

use common::from_hex;
use common::read_fixture;
use common::text_of;

#[test]
fn integers_match_bouncy_castle() {
    let fixture = read_fixture();
    let cases = fixture["integers"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let value = BigInt::from_str(text_of(&case["value"])).unwrap();
        let ours = ua_cryptography_der::integer(&value);
        assert_eq!(ours, from_hex(text_of(&case["der"])), "INTEGER {value}");
        assert_eq!(Asn1Node::parse(&ours).unwrap().to_integer().unwrap(), value);
    }
}

#[test]
fn object_identifiers_match_bouncy_castle() {
    let fixture = read_fixture();
    let cases = fixture["objectIdentifiers"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let oid = text_of(&case["oid"]);
        let ours = ua_cryptography_der::object_identifier(oid);
        assert_eq!(ours, from_hex(text_of(&case["der"])), "OID {oid}");
        assert_eq!(Asn1Node::parse(&ours).unwrap().to_oid().unwrap(), oid);
    }
}

#[test]
fn length_forms_match_bouncy_castle() {
    let fixture = read_fixture();
    let cases = fixture["octetStringHeaders"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let length = case["length"].as_u64().unwrap() as usize;
        let content: Vec<u8> = (0..length).map(|index| (index * 31 + 7) as u8).collect();
        let mut expected = from_hex(text_of(&case["header"]));
        expected.extend_from_slice(&content);
        let ours = ua_cryptography_der::octet_string(&content);
        assert_eq!(ours, expected, "OCTET STRING of {length} octets");
        assert_eq!(Asn1Node::parse(&ours).unwrap().to_octet_string().unwrap(), content);
    }
}

#[test]
fn set_of_is_sorted_like_bouncy_castle() {
    let fixture = read_fixture();
    let rounds = fixture["setsOf"].as_array().unwrap();
    assert_eq!(rounds.len(), 50);
    for round in rounds {
        let items: Vec<Vec<u8>> = round["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| from_hex(text_of(item)))
            .collect();
        assert_eq!(ua_cryptography_der::set_of(&items), from_hex(text_of(&round["der"])));
    }
}

#[test]
fn named_bits_match_bouncy_castle() {
    let fixture = read_fixture();
    let cases = fixture["keyUsages"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        // BouncyCastle numbers the bits of the first octet from the most significant one; ours from bit 0.
        let bouncy_castle = from_hex(text_of(&case["der"]));
        let bits = Asn1Node::parse(&bouncy_castle).unwrap().to_named_bits().unwrap();
        assert_eq!(
            ua_cryptography_der::named_bits(bits),
            bouncy_castle,
            "key usage {}",
            case["bouncyCastleBits"]
        );
    }
}

#[test]
fn times_match_bouncy_castle() {
    let fixture = read_fixture();
    let times = &fixture["times"];
    let at = datetime!(2026-10-10 12:34:56 UTC);
    assert_eq!(ua_cryptography_der::utc_time(at), from_hex(text_of(&times["utcTime"])));
    assert_eq!(
        ua_cryptography_der::generalized_time(at),
        from_hex(text_of(&times["generalizedTime"]))
    );
    assert_eq!(
        Asn1Node::parse(&ua_cryptography_der::utc_time(at))
            .unwrap()
            .to_time()
            .unwrap(),
        at
    );
    assert_eq!(
        Asn1Node::parse(&ua_cryptography_der::generalized_time(at))
            .unwrap()
            .to_time()
            .unwrap(),
        at
    );
    let last_century = datetime!(1999-01-02 03:04:05 UTC);
    assert_eq!(
        Asn1Node::parse(&ua_cryptography_der::x509_time(last_century))
            .unwrap()
            .to_time()
            .unwrap(),
        last_century
    );
    assert_eq!(
        ua_cryptography_der::x509_time(datetime!(2050-01-01 00:00 UTC))[0],
        ua_cryptography_der::tag::GENERALIZED_TIME
    );
}

#[test]
fn ber_indefinite_length_and_constructed_strings_are_read() {
    // SEQUENCE (indefinite) { OCTET STRING (constructed, indefinite) { "ab", "cd" }, INTEGER 5 }
    let fixture = read_fixture();
    let ber = from_hex(text_of(&fixture["berSequence"]));
    assert_eq!(ber[1], 0x80, "really indefinite");

    let node = Asn1Node::parse(&ber).unwrap();
    let children = node.children().unwrap();
    assert_eq!(children.len(), 2);
    assert_eq!(children[0].to_octet_string().unwrap(), b"abcd");
    assert_eq!(children[1].to_i32().unwrap(), 5);
    assert_eq!(node.encoded(), ber);
}

#[test]
fn malformed_input_is_refused() {
    let cases = [
        ("30", DerError::Truncated),                        // no length
        ("3005020101", DerError::LengthExceedsData),        // shorter than its length
        ("0201", DerError::LengthExceedsData),              // INTEGER without contents
        ("02010100", DerError::TrailingBytes { count: 1 }), // trailing byte
        ("1F0100", DerError::HighTagNumber),                // high tag number
        ("3080020101", DerError::MissingEndOfContents),     // missing end-of-contents
        ("0485FFFFFFFFFF", DerError::InvalidLength),        // length beyond 32 bits
    ];
    for (hex, expected) in cases {
        let data = from_hex(hex);
        let outcome = Asn1Node::parse(&data).and_then(|node| {
            if node.is_constructed() {
                node.children().map(|children| children.len())
            } else {
                node.to_integer().map(|_| 0)
            }
        });
        assert_eq!(outcome, Err(expected), "{hex}");
    }
}

#[test]
fn deep_nesting_is_refused() {
    let mut data = vec![0x04, 0x00];
    for _ in 0..100 {
        data = ua_cryptography_der::sequence([data]);
    }
    let mut node = Asn1Node::parse(&data).unwrap();
    let mut refusal = None;
    for _ in 0..100 {
        match node.child(0) {
            Ok(child) => node = child,
            Err(error) => {
                refusal = Some(error);
                break;
            }
        }
    }
    assert_eq!(refusal, Some(DerError::TooDeep));
}
