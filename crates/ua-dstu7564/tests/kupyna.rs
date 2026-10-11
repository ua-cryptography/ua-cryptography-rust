//! Kupyna against the examples of DSTU 7564:2014 and BouncyCastle (recorded answers).

use serde_json::Value;
use ua_dstu7564::HashSize;
use ua_dstu7564::Kupyna;
use ua_dstu7564::UnsupportedHashSizeError;

const ORACLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/oracle/dstu7564-bc/dstu7564-bc.json"
);

/// Examples of DSTU 7564:2014 / the Kupyna paper (Oliynykov et al., 2015), as in BouncyCastle's DSTU7564Test.
/// "seq:n" stands for the n bytes 00 01 02 … (n − 1).
const STANDARD_EXAMPLES: [(usize, &str, &str); 13] = [
    (
        256,
        "seq:64",
        "08F4EE6F1BE6903B324C4E27990CB24EF69DD58DBE84813EE0A52F6631239875",
    ),
    (
        256,
        "seq:128",
        "0A9474E645A7D25E255E9E89FFF42EC7EB31349007059284F0B182E452BDA882",
    ),
    (
        256,
        "seq:256",
        "D305A32B963D149DC765F68594505D4077024F836C1BF03806E1624CE176C08F",
    ),
    (
        256,
        "FF",
        "EA7677CA4526555680441C117982EA14059EA6D0D7124D6ECDB3DEEC49E890F4",
    ),
    (
        256,
        "seq:95",
        "1075C8B0CB910F116BDA5FA1F19C29CF8ECC75CAFF7208BA2994B68FC56E8D16",
    ),
    (
        256,
        "seq:0",
        "CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6",
    ),
    (
        384,
        "seq:95",
        "D9021692D84E5175735654846BA751E6D0ED0FAC36DFBC0841287DCB0B5584C75016C3DECC2A6E47C50B2F3811E351B8",
    ),
    (
        512,
        "seq:64",
        "3813E2109118CDFB5A6D5E72F7208DCCC80A2DFB3AFDFB02F46992B5EDBE536B3560DD1D7E29C6F53978AF58B444E37BA685C0DD910533BA5D78EFFFC13DE62A",
    ),
    (
        512,
        "seq:128",
        "76ED1AC28B1D0143013FFA87213B4090B356441263C13E03FA060A8CADA32B979635657F256B15D5FCA4A174DE029F0B1B4387C878FCC1C00E8705D783FD7FFE",
    ),
    (
        512,
        "seq:256",
        "0DD03D7350C409CB3C29C25893A0724F6B133FA8B9EB90A64D1A8FA93B56556611EB187D715A956B107E3BFC76482298133A9CE8CBC0BD5E1436A5B197284F7E",
    ),
    (
        512,
        "FF",
        "871B18CF754B72740307A97B449ABEB32B64444CC0D5A4D65830AE5456837A72D8458F12C8F06C98C616ABE11897F86263B5CB77C420FB375374BEC52B6D0292",
    ),
    (
        512,
        "seq:192",
        "B189BFE987F682F5F167F0D7FA565330E126B6E592B1C55D44299064EF95B1A57F3C2D0ECF17869D1D199EBBD02E8857FB8ADD67A8C31F56CD82C016CF743121",
    ),
    (
        512,
        "seq:0",
        "656B2F4CD71462388B64A37043EA55DBE445D452AECD46C3298343314EF04019BCFA3F04265A9857F91BE91FCE197096187CEDA78C9C1C021C294A0689198538",
    ),
];

#[test]
fn the_examples_of_the_standard_are_reproduced() {
    for (bits, message, expected) in STANDARD_EXAMPLES {
        let size = HashSize::from_bits(bits).unwrap();
        let hash = Kupyna::calculate_hash(&example_message(message), size);
        assert_eq!(hash, from_hex(expected), "{bits} bits, {message}");
    }
}

#[test]
fn ascii_messages_hash_to_their_known_values() {
    let cases = [
        ("", "CD5101D1CCDF0D1D1F4ADA56E888CD724CA1A0838A3521E7131D4FB78D0F5EB6"),
        ("a", "C51A1D639596FB613D86557314A150C40F8FFF3DE48BC93A3B03C161F4105EE4"),
        (
            "abc",
            "0BD1B36109F1318411A0517315AA46B8839DF06622A278676F5487996C9CFC04",
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "02621DBB53F2C7001BE64D7308ECB80D21BA7797C92E98D1EFC240D41E4C414B",
        ),
    ];
    for (message, expected) in cases {
        assert_eq!(
            Kupyna::calculate_hash(message.as_bytes(), HashSize::Bits256),
            from_hex(expected),
            "{message:?}"
        );
    }
}

#[test]
fn every_size_matches_bouncy_castle_around_the_block_and_length_field_boundaries() {
    let oracle: Value = serde_json::from_str(&std::fs::read_to_string(ORACLE).unwrap()).unwrap();
    let cases = oracle.as_array().unwrap();
    assert_eq!(cases.len(), 48);
    for case in cases {
        let size = HashSize::from_bits(case["bits"].as_u64().unwrap() as usize).unwrap();
        let message = from_hex(case["message"].as_str().unwrap());
        let mut hasher = Kupyna::new(size);
        assert_eq!(
            hasher.hash(&message),
            from_hex(case["hash"].as_str().unwrap()),
            "{size:?}, {} bytes",
            message.len()
        );
    }
}

#[test]
fn incremental_hashing_matches_one_shot() {
    let data = pseudo_random_bytes(1001, 2);
    for size in [HashSize::Bits256, HashSize::Bits512] {
        let mut hasher = Kupyna::new(size);
        let mut offset = 0;
        for chunk in [1, 63, 2, 128, 300, 7] {
            hasher.update(&data[offset..offset + chunk]);
            offset += chunk;
        }
        hasher.update(&data[offset..]);
        assert_eq!(hasher.finalize(), Kupyna::calculate_hash(&data, size), "{size:?}");
    }
}

#[test]
fn finalizing_resets_the_hash_for_the_next_message() {
    let mut hasher = Kupyna::new(HashSize::Bits384);
    hasher.update(b"first message");
    hasher.finalize();
    hasher.update(b"abc");
    assert_eq!(hasher.finalize(), Kupyna::calculate_hash(b"abc", HashSize::Bits384));
}

#[test]
fn an_unsupported_size_is_refused() {
    assert_eq!(HashSize::from_bits(128), Err(UnsupportedHashSizeError { bits: 128 }));
    assert_eq!(HashSize::from_bits(384).map(HashSize::bytes), Ok(48));
}

fn example_message(spec: &str) -> Vec<u8> {
    match spec.strip_prefix("seq:") {
        Some(length) => (0..length.parse::<usize>().unwrap()).map(|i| i as u8).collect(),
        None => from_hex(spec),
    }
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
