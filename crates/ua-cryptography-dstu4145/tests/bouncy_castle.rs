//! The polynomial basis against BouncyCastle, an independent implementation of DSTU 4145, through the answers
//! recorded by tools/csharp-oracle (testdata/oracle/dstu4145-bc).

use num_bigint::BigUint;
use serde_json::Value;
use ua_cryptography_dstu4145::{
    DomainParameters, Signer, encode_signature, get_polynomial_curve, hash_to_field_element,
};
use ua_cryptography_gf2m::{CurvePoint, FieldBasis, parse_hex, parse_hex_bytes};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/oracle/dstu4145-bc/dstu4145-bc.json"
);

fn read_curves() -> Vec<Value> {
    let text = std::fs::read_to_string(FIXTURE).unwrap();
    let fixture: Value = serde_json::from_str(&text).unwrap();
    fixture["curves"].as_array().unwrap().clone()
}

fn hex(value: &Value) -> BigUint {
    parse_hex(value.as_str().unwrap()).unwrap()
}

fn ours(curve: &Value) -> DomainParameters {
    get_polynomial_curve(curve["m"].as_u64().unwrap() as u32).unwrap()
}

#[test]
fn the_named_curves_match_bouncy_castle() {
    let curves = read_curves();
    assert_eq!(10, curves.len());
    for curve in &curves {
        let parameters = ours(curve);
        let index = curve["index"].as_u64().unwrap() as usize;
        assert_eq!(
            parameters,
            ua_cryptography_dstu4145::get_polynomial_curve_by_index(index).unwrap(),
            "OID index {index}"
        );

        let FieldBasis::Polynomial(basis) = parameters.field().basis() else {
            panic!("Г.1 is in a polynomial basis")
        };
        assert_eq!(curve["k1"].as_u64().unwrap(), u64::from(basis.k()), "{index}");
        assert_eq!(curve["k2"].as_u64().unwrap(), u64::from(basis.j()), "{index}");
        assert_eq!(curve["k3"].as_u64().unwrap(), u64::from(basis.l()), "{index}");
        assert_eq!(hex(&curve["a"]), parameters.curve().a().to_biguint(), "{index}");
        assert_eq!(hex(&curve["b"]), parameters.curve().b().to_biguint(), "{index}");
        assert_eq!(hex(&curve["n"]), *parameters.n(), "{index}");
        assert_eq!(
            hex(&curve["gx"]),
            parameters.base_point().x().unwrap().to_biguint(),
            "{index}"
        );
        assert_eq!(
            hex(&curve["gy"]),
            parameters.base_point().y().unwrap().to_biguint(),
            "{index}"
        );
    }
}

#[test]
fn scalar_multiplication_matches_bouncy_castle() {
    for curve in &read_curves() {
        let parameters = ours(curve);
        for multiple in curve["multiples"].as_array().unwrap() {
            let actual = parameters
                .curve()
                .multiply(parameters.base_point(), &hex(&multiple["k"]));
            assert_eq!(
                hex(&multiple["x"]),
                actual.x().unwrap().to_biguint(),
                "m = {}",
                curve["m"]
            );
            assert_eq!(
                hex(&multiple["y"]),
                actual.y().unwrap().to_biguint(),
                "m = {}",
                curve["m"]
            );
        }
    }
}

#[test]
fn bouncy_castle_signatures_verify() {
    for curve in &read_curves() {
        let parameters = ours(curve);
        let signer = Signer::new(&parameters);
        for signature in curve["bouncyCastleSignatures"].as_array().unwrap() {
            let q =
                CurvePoint::from_biguint(parameters.curve(), &hex(&signature["qx"]), &hex(&signature["qy"])).unwrap();
            // BouncyCastle reverses the hash it is given; the fixture holds it most significant byte first.
            let hash = parse_hex_bytes(signature["hash"].as_str().unwrap()).unwrap();
            let h = hash_to_field_element(&hash, parameters.field());
            let (r, s) = (hex(&signature["r"]), hex(&signature["s"]));
            assert!(signer.verify(&q, &h, &r, &s), "m = {}", curve["m"]);
        }
    }
}

/// BouncyCastle verified these signatures of the C# library while recording; producing the same (r, s) and D from
/// the same key, hash and presignature makes the signatures of this crate verifiable by BouncyCastle too.
#[test]
fn signatures_with_a_fixed_presignature_equal_the_ones_bouncy_castle_verified() {
    for curve in &read_curves() {
        let parameters = ours(curve);
        let signer = Signer::new(&parameters);
        for recorded in curve["csharpSignatures"].as_array().unwrap() {
            assert!(recorded["bouncyCastleVerified"].as_bool().unwrap());
            let d = hex(&recorded["d"]);
            let q = signer.calculate_public_key(&d).unwrap();
            assert_eq!(hex(&recorded["qx"]), q.x().unwrap().to_biguint(), "m = {}", curve["m"]);
            assert_eq!(hex(&recorded["qy"]), q.y().unwrap().to_biguint(), "m = {}", curve["m"]);

            let hash = parse_hex_bytes(recorded["hash"].as_str().unwrap()).unwrap();
            let h = hash_to_field_element(&hash, parameters.field());
            let presignature = signer.calculate_presignature(&hex(&recorded["e"])).unwrap();
            let (r, s) = signer.sign(&d, &h, &presignature).unwrap().unwrap();
            assert_eq!(hex(&recorded["r"]), r, "m = {}", curve["m"]);
            assert_eq!(hex(&recorded["s"]), s, "m = {}", curve["m"]);

            let signature = encode_signature(&r, &s, parameters.minimum_signature_bits()).unwrap();
            assert_eq!(
                parse_hex_bytes(recorded["signature"].as_str().unwrap()).unwrap(),
                signature
            );
            assert!(signer.verify_hash(&q, &hash, &signature), "m = {}", curve["m"]);
        }
    }
}
