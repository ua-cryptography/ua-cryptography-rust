//! Known answers: the worked examples of Appendix Б of DSTU 4145-2002, checked value by value.

use num_bigint::BigUint;
use ua_cryptography_dstu4145::{DomainParameters, Signer, encode_signature, hash_to_field_element};
use ua_cryptography_gf2m::{BinaryCurve, BinaryField, CurvePoint, format_hex, parse_hex, parse_hex_bytes};

struct Example {
    name: &'static str,
    field: fn() -> BinaryField,
    a: u32,
    b: &'static str,
    n: &'static str,
    px: &'static str,
    py: &'static str,
    d: &'static str,
    qx: &'static str,
    qy: &'static str,
    hash: &'static str,
    h_element: &'static str,
    e: &'static str,
    epx: &'static str,
    epy: &'static str,
    y: &'static str,
    r: &'static str,
    s: &'static str,
    signature_bits: u32,
    signature: &'static str,
}

/// Б.1: polynomial basis, GF(2^163), x^163 + x^7 + x^6 + x^3 + 1.
const B1: Example = Example {
    name: "Б.1 (PB, m = 163)",
    field: || BinaryField::polynomial(163, 3, 6, 7).unwrap(),
    a: 1,
    b: "5FF6108462A2DC8210AB403925E638A19C1455D21",
    n: "400000000000000000002BEC12BE2262D39BCF14D",
    px: "72D867F93A93AC27DF9FF01AFFE74885C8C540420",
    py: "0224A9C3947852B97C5599D5F4AB81122ADC3FD9B",
    d: "183F60FDF7951FF47D67193F8D073790C1C9B5A3E",
    // The printed standard misses one digit of x_Q ("...ABD2DA").
    qx: "057DE7FDE023FF929CB6AC785CE4B79CF64ABDC2DA",
    qy: "3E85444324BCF06AD85ABF6AD7B5F34770532B9AA",
    hash: "09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF",
    h_element: "03A2EB95B7180166DDF73532EEB76EDAEF52247FF",
    e: "1025E40BD97DB012B7A1D79DE8E12932D247F61C6",
    epx: "42A7D756D70E1C9BA62D2CB43707C35204EF3C67C",
    epy: "5310AE5E560464A95DC80286F17EB762EC544B15B",
    y: "274EA2C0CAA014A0D80A424F59ADE7A93068D08A7",
    r: "274EA2C0CAA014A0D80A424F59ADE7A93068D08A7",
    s: "2100D86957331832B8E8C230F5BD6A332B3615ACA",
    signature_bits: 512,
    signature: "000000000000000000000002100D86957331832B8E8C230F5BD6A332B3615ACA000\
                00000000000000000000274EA2C0CAA014A0D80A424F59ADE7A93068D08A7",
};

/// Б.2: optimal normal basis, GF(2^173).
const B2: Example = Example {
    name: "Б.2 (ONB, m = 173)",
    field: || BinaryField::optimal_normal(173).unwrap(),
    a: 0,
    b: "043D7E139319F43BA00944915740E1E6651B06E278C7",
    n: "800000000000000000000189B4E67606E3825BB2831",
    px: "1D26E5282C2647E1B0327CB4F6087932A0A1F006A89F",
    py: "0322218E4551CF8F6E3345644A10B2408F5DF19EC2C7",
    d: "49FF09C848613AEA23699F78C960D5174617311ADCC",
    qx: "16C1FF796B32D6D2FC83CA9530B368B322F7874B2D01",
    qy: "1F253334197826B6ADAE44EDEAA7EA281D1C5E597A37",
    hash: "2A681ECE118389B27A108137187EA862117EF1484289470ECAC802C5A651FDA8",
    h_element: "0137187EA862117EF1484289470ECAC802C5A651FDA8",
    e: "70516411E5D9886B8486ECE54A30E9403D103B95F90",
    epx: "028886EA28A7C2951FA6473EB3EBC861D3EDB1FBB031",
    epy: "19059E90F7C7725079CFFE312A389B265140F5BDA493",
    y: "0477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A",
    r: "477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A",
    s: "472EA56AE478F95F1EC9F628FF43857E168B50FB819",
    signature_bits: 352,
    signature: "0472EA56AE478F95F1EC9F628FF43857E168B50FB819\
                0477ECC260F390FB6D0AE4AE3B7A78120F8EC458EF9A",
};

const EXAMPLES: [Example; 2] = [B1, B2];

fn h(text: &str) -> BigUint {
    parse_hex(text).unwrap()
}

fn set_up(x: &Example) -> (DomainParameters, Signer) {
    let field = (x.field)();
    let curve = BinaryCurve::from_biguint(&field, x.a, &h(x.b)).unwrap();
    let p = CurvePoint::from_hex(&curve, x.px, x.py).unwrap();
    let parameters = DomainParameters::new(&curve, &p, &h(x.n)).unwrap();
    let signer = Signer::new(&parameters);
    (parameters, signer)
}

#[test]
fn the_base_point_has_order_n_and_the_parameters_pass_section_8() {
    for x in &EXAMPLES {
        let (parameters, _) = set_up(x);
        assert!(
            parameters
                .curve()
                .multiply(parameters.base_point(), parameters.n())
                .is_infinity(),
            "{}",
            x.name
        );
        assert_eq!(Ok(()), parameters.validate(), "{}", x.name);
    }
}

#[test]
fn the_public_key_is_minus_d_p() {
    for x in &EXAMPLES {
        let (parameters, signer) = set_up(x);
        let q = signer.calculate_public_key(&h(x.d)).unwrap();
        assert_eq!(h(x.qx), q.x().unwrap().to_biguint(), "{}", x.name);
        assert_eq!(h(x.qy), q.y().unwrap().to_biguint(), "{}", x.name);
        assert_eq!(Ok(()), parameters.validate_public_key(&q), "{}", x.name);
    }
}

#[test]
fn the_hash_becomes_a_field_element_by_its_low_bits() {
    for x in &EXAMPLES {
        let (parameters, _) = set_up(x);
        let element = hash_to_field_element(&parse_hex_bytes(x.hash).unwrap(), parameters.field());
        assert_eq!(h(x.h_element), element.to_biguint(), "{}", x.name);
    }
}

#[test]
fn the_presignature_is_the_x_of_e_p() {
    for x in &EXAMPLES {
        let (_, signer) = set_up(x);
        let presignature = signer.calculate_presignature(&h(x.e)).unwrap();
        assert_eq!(h(x.epx), presignature.fe.to_biguint(), "{}", x.name);
    }
}

#[test]
fn the_signature_matches_every_intermediate_value() {
    for x in &EXAMPLES {
        let (parameters, signer) = set_up(x);
        let element = hash_to_field_element(&parse_hex_bytes(x.hash).unwrap(), parameters.field());
        let presignature = signer.calculate_presignature(&h(x.e)).unwrap();

        let y = &element * &presignature.fe;
        assert_eq!(h(x.y), y.to_biguint(), "{}", x.name);

        let (r, s) = signer.sign(&h(x.d), &element, &presignature).unwrap().unwrap();
        assert_eq!(h(x.r), r, "{}", x.name);
        assert_eq!(h(x.s), s, "{}", x.name);

        let d = encode_signature(&r, &s, x.signature_bits).unwrap();
        assert_eq!(x.signature, format_hex_bytes(&d), "{}", x.name);
    }
}

#[test]
fn the_signature_of_the_standard_verifies() {
    for x in &EXAMPLES {
        let (parameters, signer) = set_up(x);
        let curve = parameters.curve();
        let q = CurvePoint::from_hex(curve, x.qx, x.qy).unwrap();

        // R = sP + rQ must equal eP.
        let r_point = &curve.multiply(parameters.base_point(), &h(x.s)) + &curve.multiply(&q, &h(x.r));
        assert_eq!(h(x.epx), r_point.x().unwrap().to_biguint(), "{}", x.name);
        assert_eq!(h(x.epy), r_point.y().unwrap().to_biguint(), "{}", x.name);

        let hash = parse_hex_bytes(x.hash).unwrap();
        assert!(
            signer.verify_hash(&q, &hash, &parse_hex_bytes(x.signature).unwrap()),
            "{}",
            x.name
        );
    }
}

#[test]
fn a_tampered_signature_or_hash_is_rejected() {
    for x in &EXAMPLES {
        let (parameters, signer) = set_up(x);
        let q = CurvePoint::from_hex(parameters.curve(), x.qx, x.qy).unwrap();
        let hash = parse_hex_bytes(x.hash).unwrap();
        let signature = parse_hex_bytes(x.signature).unwrap();

        for i in (0..signature.len()).step_by(7) {
            let mut bad = signature.clone();
            bad[i] ^= 0x10;
            assert!(!signer.verify_hash(&q, &hash, &bad), "{}: byte {i}", x.name);
        }

        let mut bad_hash = hash.clone();
        *bad_hash.last_mut().unwrap() ^= 1;
        assert!(!signer.verify_hash(&q, &bad_hash, &signature), "{}", x.name);
    }
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    let digits = format_hex(&BigUint::from_bytes_be(bytes));
    format!("{digits:0>width$}", width = 2 * bytes.len())
}
