//! The random bit generator of Appendix А.

use rand_core::RngCore;
use ua_dstu4145::{RandomGenerator, Signer, get_optimal_normal_curve};

#[test]
fn the_generator_is_deterministic_for_a_fixed_state() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let seed = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut a = RandomGenerator::new(&key, &seed, Some(0x0123_4567_89AB_CDEF), None).unwrap();
    let mut b = RandomGenerator::new(&key, &seed, Some(0x0123_4567_89AB_CDEF), None).unwrap();
    let mut c = RandomGenerator::new(&key, &seed, Some(0x0123_4567_89AB_CDEE), None).unwrap();
    let (mut ra, mut rb, mut rc) = ([0u8; 64], [0u8; 64], [0u8; 64]);
    a.fill_bytes(&mut ra);
    b.fill_bytes(&mut rb);
    c.fill_bytes(&mut rc);
    assert_eq!(ra, rb);
    assert_ne!(ra, rc);
}

#[test]
fn the_output_looks_balanced() {
    let mut generator = RandomGenerator::from_os_entropy();
    let mut bytes = [0u8; 2048];
    generator.fill_bytes(&mut bytes);
    let ones: u32 = bytes.iter().map(|byte| byte.count_ones()).sum();
    // 16384 bits: 8192 ± 4.5 sigma (sigma = 64)
    assert!((8192 - 290..=8192 + 290).contains(&ones), "{ones} ones");
}

#[test]
fn the_signer_works_with_the_standard_generator() {
    let parameters = get_optimal_normal_curve(173).unwrap();
    let mut signer = Signer::with_rng(&parameters, RandomGenerator::from_os_entropy());
    let key = signer.generate_key_pair();
    let message = "Тестове повідомлення".as_bytes();
    let signature = signer.sign_message(&key.private_key, message).unwrap();
    assert!(signer.verify_message(&key.public_key, message, &signature));
}

#[test]
fn the_generator_reproduces_the_reference_output() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/oracle/dstu4145-bc/dstu4145-bc.json"
    );
    let fixture: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let recorded = &fixture["randomGenerator"];
    let bytes = |name: &str| ua_gf2m::parse_hex_bytes(recorded[name].as_str().unwrap()).unwrap();
    let key: [u8; 32] = bytes("key").try_into().unwrap();
    let seed: [u8; 8] = bytes("seed").try_into().unwrap();
    let date_time = u64::from_str_radix(recorded["dateTime"].as_str().unwrap(), 16).unwrap();

    let mut generator = RandomGenerator::new(&key, &seed, Some(date_time), None).unwrap();
    let mut output = [0u8; 64];
    generator.fill_bytes(&mut output);
    assert_eq!(bytes("output"), output);
}
