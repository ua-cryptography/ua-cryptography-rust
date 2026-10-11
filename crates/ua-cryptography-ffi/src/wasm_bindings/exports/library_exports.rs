use wasm_bindgen::prelude::wasm_bindgen;

/// The library version, e.g. "0.1.0".
#[wasm_bindgen(js_name = getVersion)]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}
