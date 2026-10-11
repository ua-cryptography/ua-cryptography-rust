//! JKS key stores, certificates, and signing and verifying files offline: the browser build reaches no service,
//! so it signs at level B and verifies with the certificates given.

use js_sys::Array;
use time::OffsetDateTime;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use crate::models::{KeyStoreRequest, SigningOptions, SigningRequest, VerificationRequest};
use crate::operations::{certificate_details, key_store, signing, verification};
use crate::utils::to_json;
use crate::wasm_bindings::js_inputs::{parse_report, read_byte_arrays, read_files, to_js_error};
use crate::wasm_bindings::types::{CreatedKeyStoreJs, SignatureFormatJs, SignatureHashJs, SignatureLevelJs};

/// The alias of a new key when the caller names none, as `ua-sign keygen` names it.
const DEFAULT_ALIAS: &str = "key";

#[wasm_bindgen(typescript_custom_section)]
const NAMED_BYTES: &str = r#"
/** A file: its name, as a XAdES reference or an ASiC entry names it, and its content. */
export interface NamedBytes {
  name: string;
  content: Uint8Array;
}
"#;

/// A new JKS store protected by `password` (the key too), with a DSTU 4145 key on the curve m of table Г.1 and
/// its self-signed certificate; `alias` defaults to "key".
#[wasm_bindgen(js_name = createKeyStore)]
pub fn create_key_store(
    subject: String,
    alias: Option<String>,
    m: u32,
    #[wasm_bindgen(js_name = validityDays)] validity_days: u32,
    #[wasm_bindgen(js_name = signatureHash)] signature_hash: SignatureHashJs,
    password: String,
) -> Result<CreatedKeyStoreJs, JsValue> {
    let request = KeyStoreRequest {
        subject,
        alias: match alias {
            Some(alias) => alias,
            None => DEFAULT_ALIAS.to_owned(),
        },
        m,
        validity_days,
        signature_hash: signature_hash.into(),
        password,
    };
    let created = key_store::create_key_store(&request, OffsetDateTime::now_utc()).map_err(to_js_error)?;
    Ok(CreatedKeyStoreJs {
        key_store: created.key_store,
        certificate: created.certificate,
    })
}

/// The certificate (DER) of the signing key `alias`, or of the one signing key of the store.
#[wasm_bindgen(js_name = getCertificate)]
pub fn get_certificate(
    #[wasm_bindgen(js_name = keyStore)] key_store: &[u8],
    password: &str,
    alias: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    key_store::get_certificate(key_store, password, alias.as_deref()).map_err(to_js_error)
}

/// The entries of a store: alias, kind, created, certificates.
#[wasm_bindgen(js_name = getKeyStoreEntries)]
pub fn get_key_store_entries(
    #[wasm_bindgen(js_name = keyStore)] key_store: &[u8],
    password: &str,
) -> Result<JsValue, JsValue> {
    let entries = key_store::get_key_store_entries(key_store, password).map_err(to_js_error)?;
    parse_report(to_json(&entries))
}

/// What a certificate (DER, PEM or base64) says.
#[wasm_bindgen(js_name = getCertificateDetails)]
pub fn get_certificate_details(certificate: &[u8]) -> Result<JsValue, JsValue> {
    let details = certificate_details::get_certificate_details(certificate).map_err(to_js_error)?;
    parse_report(to_json(&details))
}

/// Signs `files` at level B with the key `alias` of the store (its one signing key when absent); `certificates`
/// complete the signer's chain. CAdES and ASiC-S take one file; `isDetached` is a CAdES option.
#[wasm_bindgen(js_name = sign)]
#[allow(clippy::too_many_arguments)]
pub fn sign(
    #[wasm_bindgen(js_name = keyStore)] key_store: &[u8],
    password: &str,
    alias: Option<String>,
    #[wasm_bindgen(unchecked_param_type = "NamedBytes[]")] files: Array,
    format: SignatureFormatJs,
    level: SignatureLevelJs,
    hash: SignatureHashJs,
    #[wasm_bindgen(js_name = isDetached)] is_detached: bool,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array[]")] certificates: Array,
) -> Result<Vec<u8>, JsValue> {
    let request = SigningRequest {
        key_store: key_store.to_vec(),
        password: password.to_owned(),
        alias,
        files: read_files(&files, "A file to sign").map_err(to_js_error)?,
        certificates: read_byte_arrays(&certificates, "A certificate").map_err(to_js_error)?,
        options: SigningOptions {
            format: format.into(),
            level: level.into(),
            hash: hash.into(),
            is_detached,
            has_content_time_stamp: false,
            tsa_url: None,
            ocsp_url: None,
        },
    };
    signing::sign(&request).map_err(to_js_error)
}

/// Verifies a signature of any format offline; an invalid signature is a report with `is_valid: false`.
/// `data` holds the data of a detached signature under the names its references use.
#[wasm_bindgen(js_name = verify)]
pub fn verify(
    signature: &[u8],
    #[wasm_bindgen(unchecked_param_type = "NamedBytes[]")] data: Array,
    #[wasm_bindgen(js_name = trustAnchors, unchecked_param_type = "Uint8Array[]")] trust_anchors: Array,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array[]")] certificates: Array,
) -> Result<JsValue, JsValue> {
    let request = VerificationRequest {
        signature: signature.to_vec(),
        data: read_files(&data, "A data file").map_err(to_js_error)?,
        trust_anchors: read_byte_arrays(&trust_anchors, "A trust anchor").map_err(to_js_error)?,
        certificates: read_byte_arrays(&certificates, "A certificate").map_err(to_js_error)?,
        is_online: false,
    };
    let summary = verification::verify(&request, OffsetDateTime::now_utc()).map_err(to_js_error)?;
    parse_report(to_json(&summary))
}
