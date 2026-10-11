//! The reader's accessors, the time forms the reader accepts (as recorded from the reference implementation in
//! testdata/oracle/der-bc), the writer's remaining functions, and PEM.

mod common;

use num_bigint::BigInt;
use num_bigint::BigUint;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;
use ua_cryptography_der::Asn1Node;
use ua_cryptography_der::DerError;
use ua_cryptography_der::OidError;
use ua_cryptography_der::PemError;
use ua_cryptography_der::tag;

use common::from_hex;
use common::read_fixture;
use common::text_of;

/// The UTCTime the reference reads as 1999-01-01: it shifts the year after applying the zone offset.
const CENTURY_SHIFTED_UTC_TIME: &str = "991231233000-0100";

#[test]
fn time_texts_are_read_as_the_reference_reads_them() {
    let fixture = read_fixture();
    let cases = fixture["readerTimes"].as_array().unwrap();
    for case in cases {
        let text = text_of(&case["text"]);
        if text == CENTURY_SHIFTED_UTC_TIME {
            continue;
        }
        let element = ua_cryptography_der::encode(case["tag"].as_u64().unwrap() as u8, text.as_bytes());
        let ours = Asn1Node::parse(&element).unwrap().to_time();
        match case["utc"].as_str() {
            Some(utc) => assert_eq!(ours.unwrap(), OffsetDateTime::parse(utc, &Rfc3339).unwrap(), "{text}"),
            None => assert_eq!(ours, Err(DerError::InvalidTime { text: text.to_owned() }), "{text}"),
        }
    }
}

#[test]
fn a_utc_time_with_an_offset_across_new_year_keeps_its_century() {
    let element = ua_cryptography_der::encode(tag::UTC_TIME, CENTURY_SHIFTED_UTC_TIME.as_bytes());
    assert_eq!(
        Asn1Node::parse(&element).unwrap().to_time().unwrap(),
        datetime!(2000-01-01 00:30 UTC)
    );
}

#[test]
fn only_time_types_are_times() {
    let element = ua_cryptography_der::utf8_string("261010123456Z");
    assert_eq!(
        Asn1Node::parse(&element).unwrap().to_time(),
        Err(DerError::NotTime { tag: tag::UTF8_STRING })
    );
}

#[test]
fn character_strings_are_text() {
    let cases = [
        (ua_cryptography_der::utf8_string("Київ"), "Київ"),
        (ua_cryptography_der::printable_string("UA"), "UA"),
        (ua_cryptography_der::ia5_string("a@b.ua"), "a@b.ua"),
        (
            ua_cryptography_der::encode(tag::BMP_STRING, &[0x04, 0x1A, 0x00, 0x41]),
            "КA",
        ),
        (
            ua_cryptography_der::encode(tag::UNIVERSAL_STRING, &[0x00, 0x01, 0xF6, 0x00]),
            "\u{1F600}",
        ),
        (ua_cryptography_der::encode(tag::VISIBLE_STRING, b"v"), "v"),
        (ua_cryptography_der::encode(tag::NUMERIC_STRING, b"42"), "42"),
    ];
    for (element, text) in cases {
        assert_eq!(Asn1Node::parse(&element).unwrap().to_text().unwrap(), text);
    }
}

#[test]
fn ascii_strings_write_other_characters_as_question_marks() {
    assert_eq!(
        ua_cryptography_der::printable_string("Ї1"),
        [tag::PRINTABLE_STRING, 0x02, b'?', b'1']
    );
    assert_eq!(
        ua_cryptography_der::ia5_string("\u{1F600}"),
        [tag::IA5_STRING, 0x01, b'?']
    );
}

#[test]
fn booleans_round_trip_and_any_non_zero_octet_is_true() {
    assert_eq!(ua_cryptography_der::boolean(true), [0x01, 0x01, 0xFF]);
    assert!(
        !Asn1Node::parse(&ua_cryptography_der::boolean(false))
            .unwrap()
            .to_boolean()
            .unwrap()
    );
    assert!(Asn1Node::parse(&[0x01, 0x01, 0x01]).unwrap().to_boolean().unwrap());
    assert_eq!(
        Asn1Node::parse(&[0x01, 0x02, 0x00, 0x00]).unwrap().to_boolean(),
        Err(DerError::InvalidBoolean)
    );
}

#[test]
fn integers_from_every_source_agree() {
    assert_eq!(
        ua_cryptography_der::integer_from_i64(-129),
        ua_cryptography_der::integer(&BigInt::from(-129))
    );
    assert_eq!(
        ua_cryptography_der::integer_from_unsigned(&BigUint::from(128u32)),
        [0x02, 0x02, 0x00, 0x80]
    );
    assert_eq!(
        ua_cryptography_der::integer_from_unsigned(&BigUint::ZERO),
        [0x02, 0x01, 0x00]
    );
    let negative = Asn1Node::parse(&[0x02, 0x01, 0xFF]).unwrap();
    assert_eq!(negative.to_unsigned_integer(), Err(DerError::NegativeInteger));
    assert_eq!(negative.to_i32().unwrap(), -1);
    let wide = ua_cryptography_der::integer_from_i64(i64::from(i32::MAX) + 1);
    assert_eq!(
        Asn1Node::parse(&wide).unwrap().to_i32(),
        Err(DerError::IntegerOutOfRange)
    );
    assert_eq!(
        Asn1Node::parse(&[0x02, 0x00]).unwrap().to_integer(),
        Err(DerError::EmptyInteger)
    );
}

#[test]
fn bit_strings_give_their_octets_after_the_unused_bits_count() {
    let element = ua_cryptography_der::bit_string(&[0xAB, 0xCD]);
    assert_eq!(element, [0x03, 0x03, 0x00, 0xAB, 0xCD]);
    assert_eq!(
        Asn1Node::parse(&element).unwrap().to_bit_string().unwrap(),
        [0xAB, 0xCD]
    );
    assert_eq!(
        Asn1Node::parse(&[0x03, 0x01, 0x08]).unwrap().to_bit_string(),
        Err(DerError::InvalidBitString)
    );
    assert_eq!(
        Asn1Node::parse(&[0x03, 0x00]).unwrap().to_bit_string(),
        Err(DerError::InvalidBitString)
    );
    assert_eq!(ua_cryptography_der::named_bits(0), [0x03, 0x01, 0x00]);
}

#[test]
fn tags_are_checked_and_context_tags_recognised() {
    let element = ua_cryptography_der::explicit(3, &ua_cryptography_der::null());
    let node = Asn1Node::parse(&element).unwrap();
    assert_eq!(node.tag(), tag::context_constructed(3));
    assert!(node.is_context(3) && node.is_constructed() && !node.is_context(0));
    assert_eq!(
        node.expect_tag(tag::SEQUENCE),
        Err(DerError::UnexpectedTag {
            expected: tag::SEQUENCE,
            found: 0xA3
        })
    );
    assert!(node.child(0).unwrap().has_tag(tag::NULL));
    let implicit = ua_cryptography_der::implicit(6, &ua_cryptography_der::ia5_string("http://x"));
    assert!(Asn1Node::parse(&implicit).unwrap().is_context(6));
    assert_eq!(tag::context_primitive(6), 0x86);
}

#[test]
fn a_missing_child_and_children_of_a_primitive_are_refused() {
    let element = ua_cryptography_der::sequence([ua_cryptography_der::null()]);
    let node = Asn1Node::parse(&element).unwrap();
    assert_eq!(
        node.child(1),
        Err(DerError::MissingChild {
            tag: tag::SEQUENCE,
            count: 1,
            index: 1
        })
    );
    let primitive = node.child(0).unwrap();
    assert_eq!(primitive.children(), Err(DerError::Primitive { tag: tag::NULL }));
}

#[test]
fn parse_first_leaves_what_follows() {
    let data = [0x05, 0x00, 0xFF, 0xFF];
    let node = Asn1Node::parse_first(&data).unwrap();
    assert_eq!(node.encoded(), [0x05, 0x00]);
}

#[test]
fn an_implicitly_tagged_octet_string_is_read_under_its_tag() {
    let element = ua_cryptography_der::implicit(0, &ua_cryptography_der::octet_string(b"key id"));
    assert_eq!(Asn1Node::parse(&element).unwrap().to_octet_string().unwrap(), b"key id");
}

#[test]
fn an_algorithm_identifier_has_no_parameters() {
    let element = ua_cryptography_der::algorithm_identifier("1.2.804.2.1.1.1.1.2.1");
    let node = Asn1Node::parse(&element).unwrap();
    assert_eq!(node.children().unwrap().len(), 1);
    assert_eq!(node.child(0).unwrap().to_oid().unwrap(), "1.2.804.2.1.1.1.1.2.1");
}

#[test]
fn object_identifier_text_from_outside_is_checked() {
    assert_eq!(
        ua_cryptography_der::encode_oid("1.2.840.113549").unwrap(),
        from_hex("2A864886F70D")
    );
    assert_eq!(ua_cryptography_der::encode_oid("CN"), Err(OidError::TooFewArcs));
    assert_eq!(
        ua_cryptography_der::decode_oid(&from_hex("2A864886F70D")).unwrap(),
        "1.2.840.113549"
    );
}

#[test]
#[should_panic(expected = "not an object identifier constant")]
fn a_malformed_object_identifier_constant_is_a_bug() {
    ua_cryptography_der::object_identifier("1.2.x");
}

#[test]
fn pem_der_and_bare_base64_all_give_the_der() {
    let der = ua_cryptography_der::sequence([ua_cryptography_der::integer_from_i64(1)]);
    let pem = ua_cryptography_der::encode_pem(&der, "CERTIFICATE");
    assert_eq!(
        pem,
        "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n"
    );
    assert_eq!(
        ua_cryptography_der::decode_pem(pem.as_bytes(), "CERTIFICATE").unwrap(),
        der
    );
    assert_eq!(ua_cryptography_der::decode_pem(&der, "CERTIFICATE").unwrap(), der);
    assert_eq!(
        ua_cryptography_der::decode_pem(b"  MAMC\r\nAQE=  ", "CMS").unwrap(),
        der
    );
    let noisy = "header\n-----BEGIN CMS-----\nMAMC AQE=\n-----END CMS-----\ntrailer";
    assert_eq!(ua_cryptography_der::decode_pem(noisy.as_bytes(), "CMS").unwrap(), der);
    assert_eq!(
        ua_cryptography_der::decode_pem(b"not base64!", "CMS"),
        Err(PemError::NotBase64 {
            label: "CMS".to_owned()
        })
    );
}
