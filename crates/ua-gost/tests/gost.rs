//! GOST 28147-89 and GOST 34.311-95 against BouncyCastle (recorded answers) and the published GOST R 34.11-94 vectors.

use serde_json::Value;
use ua_gost::DEFAULT_DKE;
use ua_gost::Gost28147;
use ua_gost::Gost34311;
use ua_gost::SubstitutionTableError;

const ORACLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/oracle/gost-bc/gost-bc.json"
);
const UCC_DKE: &str = "4A92D80E6B1C7F53EB4C6DFA23810759581DA342EFC7609B7DA1089FE46CB2536C715FD84A9E03B24BA0721D36859CFEDB413F590AE7682C1FD057A4923E6B8C";

#[test]
fn the_ucc_dke_is_the_gost_r_34_11_test_parameter_set() {
    let oracle = read_oracle();
    let expanded = Gost28147::expand_dke(&from_hex(UCC_DKE)).unwrap();
    assert_eq!(
        expanded.to_vec(),
        from_hex(text(&oracle["bouncyCastleSboxes"]["dTest"]))
    );
}

#[test]
fn the_block_cipher_matches_bouncy_castle_for_every_table() {
    for table in read_oracle()["sboxes"].as_array().unwrap() {
        let mut cipher = Gost28147::new(&from_hex(text(&table["sbox"]))).unwrap();
        for block in table["blocks"].as_array().unwrap() {
            let key: [u8; 32] = from_hex(text(&block["key"])).try_into().unwrap();
            let plaintext: [u8; 8] = from_hex(text(&block["plaintext"])).try_into().unwrap();
            cipher.set_key(&key);
            let ciphertext = cipher.encrypt_block(&plaintext);
            assert_eq!(
                ciphertext.to_vec(),
                from_hex(text(&block["ciphertext"])),
                "{}",
                table["name"]
            );
            assert_eq!(cipher.decrypt_block(&ciphertext), plaintext, "{}", table["name"]);
        }
    }
}

#[test]
fn the_hash_matches_bouncy_castle_for_every_table_around_block_boundaries() {
    for table in read_oracle()["sboxes"].as_array().unwrap() {
        let mut hasher = Gost34311::new(&from_hex(text(&table["sbox"]))).unwrap();
        for case in table["hashes"].as_array().unwrap() {
            let message = from_hex(text(&case["message"]));
            let hash = hasher.hash(&message);
            assert_eq!(
                hash.to_vec(),
                from_hex(text(&case["hash"])),
                "{} / {} bytes",
                table["name"],
                message.len()
            );
        }
    }
}

#[test]
fn incremental_hashing_matches_one_shot() {
    let data = pseudo_random_bytes(777, 1);
    let expected = Gost34311::calculate_hash(&data);

    let mut hasher = Gost34311::default();
    let mut offset = 0;
    for chunk in [1, 30, 2, 64, 100, 5] {
        hasher.update(&data[offset..offset + chunk]);
        offset += chunk;
    }
    hasher.update(&data[offset..]);
    assert_eq!(hasher.finalize(), expected);
}

#[test]
fn finalizing_resets_the_hash_for_the_next_message() {
    let mut hasher = Gost34311::default();
    hasher.update(b"first message");
    hasher.finalize();
    hasher.update(b"message digest");
    assert_eq!(hasher.finalize(), Gost34311::calculate_hash(b"message digest"));
}

#[test]
fn published_vectors_with_the_test_parameters() {
    let sbox = from_hex(text(&read_oracle()["bouncyCastleSboxes"]["dTest"]));
    let cases = [
        ("", "CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D"),
        ("a", "D42C539E367C66E9C88A801F6649349C21871B4344C6A573F849FDCE62F314DD"),
        (
            "message digest",
            "AD4434ECB18F2C99B60CBE59EC3D2469582B65273F48DE72DB2FDE16A4889A4D",
        ),
        (
            "The quick brown fox jumps over the lazy dog",
            "77B7FA410C9AC58A25F49BCA7D0468C9296529315EACA76BD1A10F376D1F4294",
        ),
    ];
    let mut hasher = Gost34311::new(&sbox).unwrap();
    for (message, expected) in cases {
        assert_eq!(
            hasher.hash(message.as_bytes()).to_vec(),
            from_hex(expected),
            "{message:?}"
        );
    }
}

#[test]
fn published_vectors_with_the_crypto_pro_parameters() {
    let sbox = from_hex(text(&read_oracle()["bouncyCastleSboxes"]["dA"]));
    let cases = [
        ("", "981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0"),
        (
            "message digest",
            "BC6041DD2AA401EBFA6E9886734174FEBDB4729AA972D60F549AC39B29721BA0",
        ),
    ];
    let mut hasher = Gost34311::new(&sbox).unwrap();
    for (message, expected) in cases {
        assert_eq!(
            hasher.hash(message.as_bytes()).to_vec(),
            from_hex(expected),
            "{message:?}"
        );
    }
}

#[test]
fn the_default_hash_is_the_hash_with_dke_no_1() {
    let mut from_dke = Gost34311::from_dke(&DEFAULT_DKE).unwrap();
    assert_eq!(from_dke.hash(b"abc"), Gost34311::calculate_hash(b"abc"));
}

#[test]
fn a_dke_of_wrong_length_is_refused() {
    assert_eq!(
        Gost34311::from_dke(&[0; 65]).err(),
        Some(SubstitutionTableError::WrongDkeLength { length: 65 })
    );
}

#[test]
fn the_initial_value_changes_the_hash() {
    let sbox = Gost28147::expand_dke(&DEFAULT_DKE).unwrap();
    let mut zero = Gost34311::with_initial_value(&sbox, &[0; 32]).unwrap();
    let mut ones = Gost34311::with_initial_value(&sbox, &[1; 32]).unwrap();
    assert_eq!(zero.hash(b"abc"), Gost34311::calculate_hash(b"abc"));
    assert_ne!(ones.hash(b"abc"), Gost34311::calculate_hash(b"abc"));
}

fn read_oracle() -> Value {
    serde_json::from_str(&std::fs::read_to_string(ORACLE).unwrap()).unwrap()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap()
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// A fixed xorshift sequence: any data will do, it only has to be the same on every run.
fn pseudo_random_bytes(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}
