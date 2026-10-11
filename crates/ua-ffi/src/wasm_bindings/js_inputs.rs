//! What JavaScript passes in and what a refusal becomes there.

use js_sys::{Array, Reflect, Uint8Array};
use ua_pki::SignedFile;
use wasm_bindgen::{JsCast, JsValue};

use crate::errors::{FailureKind, OperationFailure};
use crate::models::NamedCurve;
use crate::wasm_bindings::types::CurveBasisJs;

/// The property of a named file that holds its name.
const NAME_PROPERTY: &str = "name";
/// The property of a named file that holds its content.
const CONTENT_PROPERTY: &str = "content";

/// A refusal as a JavaScript `Error` named after its kind: InvalidArgument, UnreadableInput, WrongPassword,
/// AuthenticationFailed, ServiceFailure.
pub fn to_js_error(failure: OperationFailure) -> JsValue {
    let error = js_sys::Error::new(&failure.message);
    error.set_name(kind_name(failure.kind));
    error.into()
}

/// The curve of `basis` and `m`.
pub fn read_curve(basis: CurveBasisJs, m: u32) -> NamedCurve {
    NamedCurve { basis: basis.into(), m }
}

/// The files of an array of `{ name: string, content: Uint8Array }`.
pub fn read_files(files: &Array, what: &str) -> Result<Vec<SignedFile>, OperationFailure> {
    files
        .iter()
        .map(|file| {
            let name = Reflect::get(&file, &JsValue::from_str(NAME_PROPERTY))
                .ok()
                .and_then(|name| name.as_string())
                .ok_or_else(|| OperationFailure::invalid_argument(format!("{what} has no string \"name\".")))?;
            let content = Reflect::get(&file, &JsValue::from_str(CONTENT_PROPERTY))
                .ok()
                .and_then(|content| content.dyn_into::<Uint8Array>().ok())
                .ok_or_else(|| OperationFailure::invalid_argument(format!("{what} has no Uint8Array \"content\".")))?;
            Ok(SignedFile {
                name,
                content: content.to_vec(),
            })
        })
        .collect()
}

/// The bytes of an array of `Uint8Array`.
pub fn read_byte_arrays(arrays: &Array, what: &str) -> Result<Vec<Vec<u8>>, OperationFailure> {
    arrays
        .iter()
        .map(|array| match array.dyn_into::<Uint8Array>() {
            Ok(array) => Ok(array.to_vec()),
            Err(_) => Err(OperationFailure::invalid_argument(format!(
                "{what} is not a Uint8Array."
            ))),
        })
        .collect()
}

/// The object of a report's JSON.
pub fn parse_report(json: Vec<u8>) -> Result<JsValue, JsValue> {
    let text = match String::from_utf8(json) {
        Ok(text) => text,
        Err(error) => unreachable!("serde_json writes UTF-8: {error}"),
    };
    js_sys::JSON::parse(&text)
}

fn kind_name(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::InvalidArgument => "InvalidArgument",
        FailureKind::UnreadableInput => "UnreadableInput",
        FailureKind::WrongPassword => "WrongPassword",
        FailureKind::AuthenticationFailed => "AuthenticationFailed",
        FailureKind::ServiceFailure => "ServiceFailure",
    }
}
