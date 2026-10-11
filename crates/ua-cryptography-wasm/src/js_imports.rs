//! What WASM imports from JS: the global `fetch` (browsers, Node.js 18+) and `AbortSignal.timeout`, and the Rust
//! adapter that sends the requests of the PKI services with them. The other direction — what the page calls on the
//! module — is [`crate::js_exports`].
//!
//! A request is started and awaited in two steps, so that several requests are in flight at once: `fetch` sends
//! when it is called, not when its promise is awaited.

use js_sys::{Object, Promise, Reflect, Uint8Array};
use ua_cryptography_pki::ServiceError;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

/// The largest answer accepted: time-stamps, OCSP responses and CA certificates are a few kilobytes.
const MAX_RESPONSE_BYTES: usize = 10 << 20;
/// The time a whole request may take.
const TIMEOUT_MILLISECONDS: u32 = 30_000;
/// The scheme a secure page may not fetch, and the one it is upgraded to.
const INSECURE_SCHEME: &str = "http://";
const SECURE_SCHEME: &str = "https://";
/// The global that is true on a page served over HTTPS (absent in Node.js).
const IS_SECURE_CONTEXT: &str = "isSecureContext";
/// The fields of fetch's init object, and the one header sent.
const METHOD_FIELD: &str = "method";
const HEADERS_FIELD: &str = "headers";
const BODY_FIELD: &str = "body";
const SIGNAL_FIELD: &str = "signal";
const POST_METHOD: &str = "POST";
const CONTENT_TYPE_HEADER: &str = "Content-Type";

#[wasm_bindgen]
extern "C" {
    /// The `Response` a fetch resolves with.
    type FetchResponse;

    #[wasm_bindgen(method, getter)]
    fn ok(this: &FetchResponse) -> bool;

    #[wasm_bindgen(method, getter)]
    fn status(this: &FetchResponse) -> u16;

    #[wasm_bindgen(method, getter, js_name = statusText)]
    fn status_text(this: &FetchResponse) -> String;

    #[wasm_bindgen(method, catch, js_name = arrayBuffer)]
    fn array_buffer(this: &FetchResponse) -> Result<Promise, JsValue>;

    /// `catch`: fetch throws synchronously on a malformed URL or init.
    #[wasm_bindgen(catch, js_name = fetch)]
    fn fetch_with_init(url: &str, init: &Object) -> Result<Promise, JsValue>;

    /// `catch`: an engine without `AbortSignal.timeout` sends without a deadline rather than failing.
    #[wasm_bindgen(catch, js_namespace = AbortSignal, js_name = timeout)]
    fn abort_after(milliseconds: u32) -> Result<JsValue, JsValue>;
}

/// A request on its way: [`StartedRequest::into_answer`] awaits the body of the answer.
pub(crate) struct StartedRequest {
    url: String,
    started: Result<Promise, ServiceError>,
}

impl StartedRequest {
    /// The body of a 2xx answer, refused as [`ServiceError`] like the native HTTP clients refuse it.
    pub(crate) async fn into_answer(self) -> Result<Vec<u8>, ServiceError> {
        let url = self.url;
        let fetched = JsFuture::from(self.started?)
            .await
            .map_err(|error| transport_error(&url, &error))?;
        let response: FetchResponse = fetched.unchecked_into();
        if !response.ok() {
            return Err(ServiceError::Status {
                url,
                status: response.status(),
                reason: response.status_text(),
            });
        }
        let reading = response.array_buffer().map_err(|error| transport_error(&url, &error))?;
        let buffer = JsFuture::from(reading)
            .await
            .map_err(|error| transport_error(&url, &error))?;
        let body = Uint8Array::new(&buffer);
        if body.length() as usize > MAX_RESPONSE_BYTES {
            return Err(ServiceError::TooLarge {
                url,
                max_bytes: MAX_RESPONSE_BYTES,
            });
        }
        Ok(body.to_vec())
    }
}

/// Sends a POST of `body` with Content-Type `media_type` (RFC 3161, 3.4; RFC 6960, appendix A).
pub(crate) fn start_post(url: &str, body: &[u8], media_type: &str) -> StartedRequest {
    let url = reachable_url(url);
    let started = post_init(body, media_type)
        .and_then(|init| fetch_with_init(&url, &init))
        .map_err(|error| transport_error(&url, &error));
    StartedRequest { url, started }
}

/// Sends a GET of `url` (caIssuers).
pub(crate) fn start_get(url: &str) -> StartedRequest {
    let url = reachable_url(url);
    let started = get_init()
        .and_then(|init| fetch_with_init(&url, &init))
        .map_err(|error| transport_error(&url, &error));
    StartedRequest { url, started }
}

fn post_init(body: &[u8], media_type: &str) -> Result<Object, JsValue> {
    let init = get_init()?;
    let headers = Object::new();
    Reflect::set(&headers, &CONTENT_TYPE_HEADER.into(), &media_type.into())?;
    Reflect::set(&init, &METHOD_FIELD.into(), &POST_METHOD.into())?;
    Reflect::set(&init, &HEADERS_FIELD.into(), &headers)?;
    // A copy: a view into WASM memory would dangle once the heap grows while the request is in flight.
    Reflect::set(&init, &BODY_FIELD.into(), &Uint8Array::from(body))?;
    Ok(init)
}

fn get_init() -> Result<Object, JsValue> {
    let init = Object::new();
    if let Ok(signal) = abort_after(TIMEOUT_MILLISECONDS) {
        Reflect::set(&init, &SIGNAL_FIELD.into(), &signal)?;
    }
    Ok(init)
}

// The certificates name http:// addresses, which a page served over HTTPS may not fetch (mixed content): there the
// request goes to the same address over https://, which the Ukrainian services answer too. Node.js keeps http://.
fn reachable_url(url: &str) -> String {
    match url.strip_prefix(INSECURE_SCHEME) {
        Some(rest) if is_secure_context() => format!("{SECURE_SCHEME}{rest}"),
        _ => url.to_owned(),
    }
}

fn is_secure_context() -> bool {
    Reflect::get(&js_sys::global(), &IS_SECURE_CONTEXT.into()).is_ok_and(|value| value.is_truthy())
}

// What fetch rejected with: a TypeError for a network or CORS failure, an AbortError or TimeoutError at the deadline.
fn transport_error(url: &str, error: &JsValue) -> ServiceError {
    let message = match error.dyn_ref::<js_sys::Error>() {
        Some(error) => format!("{}: {}", String::from(error.name()), String::from(error.message())),
        None => match error.as_string() {
            Some(text) => text,
            None => format!("{error:?}"),
        },
    };
    ServiceError::Transport {
        url: url.to_owned(),
        message,
    }
}
