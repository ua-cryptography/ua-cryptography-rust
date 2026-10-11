//! The JavaScript bindings of the browser build: the operations as `#[wasm_bindgen]` functions over `Uint8Array`,
//! numbers and strings; a refusal is thrown as an `Error` whose `name` is the failure kind.

mod exports;
mod js_inputs;
mod types;
