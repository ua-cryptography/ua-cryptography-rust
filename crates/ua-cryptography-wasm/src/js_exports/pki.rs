//! JKS key stores, certificates, and signing and verifying files: `sign` and `verify` offline, `signOnline` and
//! `verifyOnline` with the PKI services asked by `fetch`.

use js_sys::Array;
use time::OffsetDateTime;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use ua_cryptography_operations::models::{KeyStoreRequest, SigningOptions, SigningRequest, VerificationRequest};
use ua_cryptography_operations::operations::{certificate_details, key_store, signing, verification};
use ua_cryptography_operations::{OperationFailure, to_json};
use ua_cryptography_pki::{SignatureLevel, SignatureServices};

use crate::js_exports::types::{CreatedKeyStoreJs, SignatureFormatJs, SignatureHashJs, SignatureLevelJs};
use crate::js_exports::{parse_report, read_byte_arrays, read_files, to_js_error};
use crate::service_answers::ServiceAnswers;

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

/// Signs `files` at level B offline with the key `alias` of the store (its one signing key when absent);
/// `certificates` complete the signer's chain. CAdES and ASiC-S take one file; `isDetached` is a CAdES option. Levels
/// T and LT are `signOnline`'s.
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
    let options = SigningOptions {
        format: format.into(),
        level: level.into(),
        hash: hash.into(),
        is_detached,
        has_content_time_stamp: false,
        tsa_url: None,
        ocsp_url: None,
    };
    if options.level > SignatureLevel::B {
        return Err(to_js_error(OperationFailure::invalid_argument(
            "sign signs at level B offline; signOnline asks the time-stamping and OCSP services for T and LT.",
        )));
    }
    let request = read_signing_request(
        key_store.to_vec(),
        password.to_owned(),
        alias,
        &files,
        &certificates,
        options,
    )
    .map_err(to_js_error)?;
    let plan = signing::plan_signature(&request).map_err(to_js_error)?;
    let services = SignatureServices {
        extra_certificates: plan.extra_certificates.clone(),
        ..SignatureServices::default()
    };
    signing::sign(&request, &plan, &services).map_err(to_js_error)
}

/// Signs `files` as `sign` does, at any level: T and a content time-stamp ask the time-stamping service (`tsaUrl`,
/// else the one the signer's certificate names), LT also the OCSP responders (`ocspUrl` for all, else each
/// certificate's) and caIssuers. Rejects with `ServiceFailure` when a service does not answer.
#[wasm_bindgen(js_name = signOnline)]
#[allow(clippy::too_many_arguments)]
pub async fn sign_online(
    #[wasm_bindgen(js_name = keyStore)] key_store: Vec<u8>,
    password: String,
    alias: Option<String>,
    #[wasm_bindgen(unchecked_param_type = "NamedBytes[]")] files: Array,
    format: SignatureFormatJs,
    level: SignatureLevelJs,
    hash: SignatureHashJs,
    #[wasm_bindgen(js_name = isDetached)] is_detached: bool,
    #[wasm_bindgen(js_name = hasContentTimeStamp)] has_content_time_stamp: bool,
    #[wasm_bindgen(js_name = tsaUrl)] tsa_url: Option<String>,
    #[wasm_bindgen(js_name = ocspUrl)] ocsp_url: Option<String>,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array[]")] certificates: Array,
) -> Result<Vec<u8>, JsValue> {
    let options = SigningOptions {
        format: format.into(),
        level: level.into(),
        hash: hash.into(),
        is_detached,
        has_content_time_stamp,
        tsa_url,
        ocsp_url,
    };
    let request =
        read_signing_request(key_store, password, alias, &files, &certificates, options).map_err(to_js_error)?;
    let plan = signing::plan_signature(&request).map_err(to_js_error)?;
    let answers = ServiceAnswers::new(plan.tsa_url.clone(), request.options.ocsp_url.clone());
    let services = answers.signature_services(&plan);
    let pending = answers
        .run_until_answered(|| signing::prepare_signature(&request, &plan, &services))
        .await
        .map_err(to_js_error)?;
    answers
        .run_until_answered(|| signing::complete_signature(&request, &plan, &pending, &services))
        .await
        .map_err(to_js_error)
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
    let request =
        read_verification_request(signature.to_vec(), &data, &trust_anchors, &certificates).map_err(to_js_error)?;
    let summary = verification::verify(&request, None, None, OffsetDateTime::now_utc()).map_err(to_js_error)?;
    parse_report(to_json(&summary))
}

/// Verifies a signature as `verify` does, asking the OCSP responders about the certificates whose status the
/// signature does not carry and downloading missing CA certificates by caIssuers. A request that fails (network,
/// CORS, a refused answer) leaves a warning on its check, not a failure.
#[wasm_bindgen(js_name = verifyOnline)]
pub async fn verify_online(
    signature: Vec<u8>,
    #[wasm_bindgen(unchecked_param_type = "NamedBytes[]")] data: Array,
    #[wasm_bindgen(js_name = trustAnchors, unchecked_param_type = "Uint8Array[]")] trust_anchors: Array,
    #[wasm_bindgen(unchecked_param_type = "Uint8Array[]")] certificates: Array,
) -> Result<JsValue, JsValue> {
    let request = read_verification_request(signature, &data, &trust_anchors, &certificates).map_err(to_js_error)?;
    let now = OffsetDateTime::now_utc();
    let answers = ServiceAnswers::new(None, None);
    let summary = answers
        .run_until_answered(|| verification::verify(&request, Some(&answers), Some(&answers), now))
        .await
        .map_err(to_js_error)?;
    parse_report(to_json(&summary))
}

fn read_signing_request(
    key_store: Vec<u8>,
    password: String,
    alias: Option<String>,
    files: &Array,
    certificates: &Array,
    options: SigningOptions,
) -> Result<SigningRequest, OperationFailure> {
    Ok(SigningRequest {
        key_store,
        password,
        alias,
        files: read_files(files, "A file to sign")?,
        certificates: read_byte_arrays(certificates, "A certificate")?,
        options,
    })
}

fn read_verification_request(
    signature: Vec<u8>,
    data: &Array,
    trust_anchors: &Array,
    certificates: &Array,
) -> Result<VerificationRequest, OperationFailure> {
    Ok(VerificationRequest {
        signature,
        data: read_files(data, "A data file")?,
        trust_anchors: read_byte_arrays(trust_anchors, "A trust anchor")?,
        certificates: read_byte_arrays(certificates, "A certificate")?,
    })
}
