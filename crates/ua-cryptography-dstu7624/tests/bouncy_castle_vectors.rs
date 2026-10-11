//! The 590 reference vectors produced by BouncyCastle Java 1.86 for every mode, block and key length.

mod common;

use std::collections::HashSet;
use std::sync::OnceLock;

use common::from_hex;
use serde_json::Value;
use ua_cryptography_dstu7624::BlockSize;
use ua_cryptography_dstu7624::Cbc;
use ua_cryptography_dstu7624::Ccm;
use ua_cryptography_dstu7624::Cfb;
use ua_cryptography_dstu7624::CipherFailure;
use ua_cryptography_dstu7624::Cmac;
use ua_cryptography_dstu7624::Ctr;
use ua_cryptography_dstu7624::Ecb;
use ua_cryptography_dstu7624::Gcm;
use ua_cryptography_dstu7624::Gmac;
use ua_cryptography_dstu7624::KeyWrap;
use ua_cryptography_dstu7624::Ofb;
use ua_cryptography_dstu7624::Xts;

const VECTORS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/vectors/dstu7624-bc-java-1.86.json"
);
const VECTOR_COUNT: usize = 590;

struct Vector {
    mode: String,
    block_size: BlockSize,
    key: Vec<u8>,
    iv: Vec<u8>,
    associated_data: Vec<u8>,
    input: Vec<u8>,
    output: Vec<u8>,
    segment_bits: usize,
    mac_bits: usize,
    nb: usize,
}

impl Vector {
    fn label(&self) -> String {
        format!(
            "{}-{}/{} in={} aad={} iv={} mac={} nb={} seg={}",
            self.mode,
            self.block_size.bits(),
            self.key.len() * 8,
            self.input.len(),
            self.associated_data.len(),
            self.iv.len(),
            self.mac_bits,
            self.nb,
            self.segment_bits
        )
    }
}

#[test]
fn all_reference_vectors_are_loaded() {
    let vectors = vectors();
    assert_eq!(vectors.len(), VECTOR_COUNT);
    let block_and_key_lengths: HashSet<(usize, usize)> = vectors
        .iter()
        .map(|vector| (vector.block_size.bits(), vector.key.len()))
        .collect();
    assert_eq!(block_and_key_lengths.len(), 5, "every block and key length");
    assert!(
        vectors
            .iter()
            .any(|vector| vector.mode == "ccm" && vector.input.len() > 255 * 16),
        "the long CCM message"
    );
}

#[test]
fn ecb_matches_bouncy_castle_java() {
    for vector in vectors_of("ecb") {
        let ecb = Ecb::new(vector.block_size, &vector.key).unwrap();
        assert_eq!(ecb.encrypt(&vector.input).unwrap(), vector.output, "{}", vector.label());
        assert_eq!(ecb.decrypt(&vector.output).unwrap(), vector.input, "{}", vector.label());
    }
}

#[test]
fn cbc_matches_bouncy_castle_java() {
    for vector in vectors_of("cbc") {
        let cbc = Cbc::new(vector.block_size, &vector.key).unwrap();
        assert_eq!(
            cbc.encrypt(&vector.iv, &vector.input).unwrap(),
            vector.output,
            "{}",
            vector.label()
        );
        assert_eq!(
            cbc.decrypt(&vector.iv, &vector.output).unwrap(),
            vector.input,
            "{}",
            vector.label()
        );
    }
}

#[test]
fn cfb_matches_bouncy_castle_java() {
    for vector in vectors_of("cfb") {
        let cfb = Cfb::with_segment(vector.block_size, &vector.key, vector.segment_bits).unwrap();
        assert_eq!(
            cfb.encrypt(&vector.iv, &vector.input).unwrap(),
            vector.output,
            "{}",
            vector.label()
        );
        assert_eq!(
            cfb.decrypt(&vector.iv, &vector.output).unwrap(),
            vector.input,
            "{}",
            vector.label()
        );
    }
}

#[test]
fn ofb_matches_bouncy_castle_java() {
    for vector in vectors_of("ofb") {
        let ofb = Ofb::with_segment(vector.block_size, &vector.key, vector.segment_bits).unwrap();
        assert_eq!(
            ofb.apply_gamma(&vector.iv, &vector.input).unwrap(),
            vector.output,
            "{}",
            vector.label()
        );
    }
}

#[test]
fn ctr_matches_bouncy_castle_java() {
    for vector in vectors_of("ctr") {
        let ctr = Ctr::new(vector.block_size, &vector.key).unwrap();
        assert_eq!(
            ctr.apply_gamma(&vector.iv, &vector.input).unwrap(),
            vector.output,
            "{}",
            vector.label()
        );
    }
}

#[test]
fn cmac_matches_bouncy_castle_java() {
    for vector in vectors_of("cmac") {
        let cmac = Cmac::new(vector.block_size, &vector.key, vector.mac_bits).unwrap();
        assert_eq!(
            cmac.calculate_mac(&vector.input).unwrap(),
            vector.output,
            "{}",
            vector.label()
        );
    }
}

#[test]
fn key_wrap_matches_bouncy_castle_java() {
    for vector in vectors_of("kw") {
        let key_wrap = KeyWrap::new(vector.block_size, &vector.key).unwrap();
        assert_eq!(
            key_wrap.wrap_key(&vector.input).unwrap(),
            vector.output,
            "{}",
            vector.label()
        );
        assert_eq!(
            key_wrap.unwrap_key(&vector.output).unwrap(),
            vector.input,
            "{}",
            vector.label()
        );
    }
}

#[test]
fn ccm_matches_bouncy_castle_java_and_refuses_a_tampered_tag() {
    for vector in vectors_of("ccm") {
        let ccm = Ccm::with_nb(vector.block_size, &vector.key, vector.nb).unwrap();
        let (nonce, associated_data, label) = (&vector.iv, &vector.associated_data, vector.label());
        assert_eq!(
            ccm.encrypt(nonce, associated_data, &vector.input, vector.mac_bits)
                .unwrap(),
            vector.output,
            "{label}"
        );
        assert_eq!(
            ccm.decrypt(nonce, associated_data, &vector.output, vector.mac_bits)
                .unwrap(),
            vector.input,
            "{label}"
        );
        let tampered = ccm.decrypt(nonce, associated_data, &flip_last_byte(&vector.output), vector.mac_bits);
        assert_eq!(tampered, Err(CipherFailure::TagMismatch), "{label}");
    }
}

#[test]
fn gcm_matches_bouncy_castle_java_and_refuses_a_tampered_tag() {
    for vector in vectors_of("gcm") {
        let gcm = Gcm::new(vector.block_size, &vector.key).unwrap();
        let (nonce, associated_data, label) = (&vector.iv, &vector.associated_data, vector.label());
        assert_eq!(
            gcm.encrypt(nonce, associated_data, &vector.input, vector.mac_bits)
                .unwrap(),
            vector.output,
            "{label}"
        );
        assert_eq!(
            gcm.decrypt(nonce, associated_data, &vector.output, vector.mac_bits)
                .unwrap(),
            vector.input,
            "{label}"
        );
        let tampered = gcm.decrypt(nonce, associated_data, &flip_last_byte(&vector.output), vector.mac_bits);
        assert_eq!(tampered, Err(CipherFailure::TagMismatch), "{label}");
    }
}

#[test]
fn gmac_matches_bouncy_castle_java() {
    for vector in vectors_of("gmac") {
        let gmac = Gmac::new(vector.block_size, &vector.key).unwrap();
        let mac = gmac.calculate_mac(&vector.iv, &vector.input, vector.mac_bits).unwrap();
        assert_eq!(mac, vector.output, "{}", vector.label());
    }
}

#[test]
fn xts_matches_bouncy_castle_java() {
    for vector in vectors_of("xts") {
        let xts = Xts::new(vector.block_size, &vector.key).unwrap();
        assert_eq!(
            xts.encrypt(&vector.iv, &vector.input).unwrap(),
            vector.output,
            "{}",
            vector.label()
        );
        assert_eq!(
            xts.decrypt(&vector.iv, &vector.output).unwrap(),
            vector.input,
            "{}",
            vector.label()
        );
    }
}

fn vectors_of(mode: &str) -> Vec<&'static Vector> {
    let selected: Vec<&Vector> = vectors().iter().filter(|vector| vector.mode == mode).collect();
    assert!(!selected.is_empty(), "no {mode} vectors");
    selected
}

fn vectors() -> &'static [Vector] {
    static VECTOR_LIST: OnceLock<Vec<Vector>> = OnceLock::new();
    VECTOR_LIST.get_or_init(|| {
        let json: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        json.as_array().unwrap().iter().map(parse_vector).collect()
    })
}

fn parse_vector(json: &Value) -> Vector {
    let hex = |name: &str| from_hex(json[name].as_str().unwrap_or(""));
    let number = |name: &str| json[name].as_u64().unwrap_or(0) as usize;
    Vector {
        mode: json["mode"].as_str().unwrap().to_owned(),
        block_size: BlockSize::from_bits(number("block")).unwrap(),
        key: hex("key"),
        iv: hex("iv"),
        associated_data: hex("aad"),
        input: hex("input"),
        output: hex("output"),
        segment_bits: number("segment"),
        mac_bits: number("macBits"),
        nb: number("nb"),
    }
}

fn flip_last_byte(data: &[u8]) -> Vec<u8> {
    let mut copy = data.to_vec();
    if let Some(last) = copy.last_mut() {
        *last ^= 1; // the last byte of the tag
    }
    copy
}
