//! DSTU 4145-2002 on the recommended curves of Appendix Г. Integers are big-endian: d, e, r, s and the signature
//! D = S‖R of 5.10; Q is compressed (6.9); a hash code is most significant byte first (5.9). `signatureBits` is
//! L_D, the shortest when absent.

use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::operations::dstu4145;
use crate::wasm_bindings::js_inputs::{read_curve, to_js_error};
use crate::wasm_bindings::types::{CurveBasisJs, KeyPairJs, SignatureHalvesJs};

/// Section 9: a random private key d (from the browser's generator) and the compressed public key Q = −dP.
#[wasm_bindgen(js_name = dstu4145GenerateKeyPair)]
pub fn dstu4145_generate_key_pair(basis: CurveBasisJs, m: u32) -> Result<KeyPairJs, JsValue> {
    let key_pair = dstu4145::generate_key_pair(read_curve(basis, m)).map_err(to_js_error)?;
    Ok(KeyPairJs {
        private_key: key_pair.private_key,
        public_key: key_pair.public_key,
    })
}

/// 9.2: the compressed Q = −dP of the private key d.
#[wasm_bindgen(js_name = dstu4145CalculatePublicKey)]
pub fn dstu4145_calculate_public_key(
    basis: CurveBasisJs,
    m: u32,
    #[wasm_bindgen(js_name = privateKey)] private_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    dstu4145::calculate_public_key(read_curve(basis, m), private_key).map_err(to_js_error)
}

/// 6.10 and 10.1: returns when the compressed key is a point of order n; throws InvalidArgument with the failed
/// clause otherwise.
#[wasm_bindgen(js_name = dstu4145ValidatePublicKey)]
pub fn dstu4145_validate_public_key(
    basis: CurveBasisJs,
    m: u32,
    #[wasm_bindgen(js_name = publicKey)] public_key: &[u8],
) -> Result<(), JsValue> {
    dstu4145::validate_public_key(read_curve(basis, m), public_key).map_err(to_js_error)
}

/// Section 12: signs a hash code with a random presignature.
#[wasm_bindgen(js_name = dstu4145SignHash)]
pub fn dstu4145_sign_hash(
    basis: CurveBasisJs,
    m: u32,
    #[wasm_bindgen(js_name = privateKey)] private_key: &[u8],
    hash: &[u8],
    #[wasm_bindgen(js_name = signatureBits)] signature_bits: Option<u32>,
) -> Result<Vec<u8>, JsValue> {
    dstu4145::sign_hash(read_curve(basis, m), private_key, hash, signature_bits).map_err(to_js_error)
}

/// Section 12 with the given secret e of the presignature: the same e gives the same signature.
#[wasm_bindgen(js_name = dstu4145SignHashWithPresignature)]
pub fn dstu4145_sign_hash_with_presignature(
    basis: CurveBasisJs,
    m: u32,
    #[wasm_bindgen(js_name = privateKey)] private_key: &[u8],
    hash: &[u8],
    e: &[u8],
    #[wasm_bindgen(js_name = signatureBits)] signature_bits: Option<u32>,
) -> Result<Vec<u8>, JsValue> {
    dstu4145::sign_hash_with_presignature(read_curve(basis, m), private_key, hash, e, signature_bits)
        .map_err(to_js_error)
}

/// Section 13: whether D is a signature of the hash code under the compressed public key.
#[wasm_bindgen(js_name = dstu4145VerifyHash)]
pub fn dstu4145_verify_hash(
    basis: CurveBasisJs,
    m: u32,
    #[wasm_bindgen(js_name = publicKey)] public_key: &[u8],
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    dstu4145::verify_hash(read_curve(basis, m), public_key, hash, signature).map_err(to_js_error)
}

/// Section 12 over H(T) by GOST 34.311 (6.2); `dke` (64 bytes) defaults to DKE No. 1.
#[wasm_bindgen(js_name = dstu4145SignMessage)]
pub fn dstu4145_sign_message(
    basis: CurveBasisJs,
    m: u32,
    #[wasm_bindgen(js_name = privateKey)] private_key: &[u8],
    message: &[u8],
    dke: Option<Vec<u8>>,
    #[wasm_bindgen(js_name = signatureBits)] signature_bits: Option<u32>,
) -> Result<Vec<u8>, JsValue> {
    dstu4145::sign_message(
        read_curve(basis, m),
        private_key,
        message,
        dke.as_deref(),
        signature_bits,
    )
    .map_err(to_js_error)
}

/// Section 13 over H(T) by GOST 34.311 (6.2); `dke` (64 bytes) defaults to DKE No. 1.
#[wasm_bindgen(js_name = dstu4145VerifyMessage)]
pub fn dstu4145_verify_message(
    basis: CurveBasisJs,
    m: u32,
    #[wasm_bindgen(js_name = publicKey)] public_key: &[u8],
    message: &[u8],
    dke: Option<Vec<u8>>,
    signature: &[u8],
) -> Result<bool, JsValue> {
    dstu4145::verify_message(read_curve(basis, m), public_key, message, dke.as_deref(), signature).map_err(to_js_error)
}

/// 5.10: (r, s) → D = S‖R of `signatureBits` bits, a positive multiple of 16.
#[wasm_bindgen(js_name = dstu4145EncodeSignature)]
pub fn dstu4145_encode_signature(
    r: &[u8],
    s: &[u8],
    #[wasm_bindgen(js_name = signatureBits)] signature_bits: u32,
) -> Result<Vec<u8>, JsValue> {
    dstu4145::encode_signature(r, s, signature_bits).map_err(to_js_error)
}

/// 5.11: D → (r, s), each half of its bits.
#[wasm_bindgen(js_name = dstu4145DecodeSignature)]
pub fn dstu4145_decode_signature(signature: &[u8]) -> Result<SignatureHalvesJs, JsValue> {
    let halves = dstu4145::decode_signature(signature).map_err(to_js_error)?;
    Ok(SignatureHalvesJs {
        r: halves.r,
        s: halves.s,
    })
}

/// Appendix А: `count` bytes of the generator with the 32-byte key, the 8-byte seed, the date and time D in .NET
/// ticks (now when absent) and the 64-byte DKE (DKE No. 1 when absent).
#[wasm_bindgen(js_name = dstu4145GenerateRandomBytes)]
pub fn dstu4145_generate_random_bytes(
    key: &[u8],
    seed: &[u8],
    #[wasm_bindgen(js_name = dateTime)] date_time: Option<u64>,
    dke: Option<Vec<u8>>,
    count: usize,
) -> Result<Vec<u8>, JsValue> {
    dstu4145::generate_random_bytes(key, seed, date_time, dke.as_deref(), count).map_err(to_js_error)
}
