use wasm_bindgen::prelude::wasm_bindgen;

use ua_cryptography_operations::operations::StreamingHash;

/// A hash fed with a message in parts, from `gost34311BeginHash` or `dstu7564BeginHash`.
#[wasm_bindgen(js_name = HashState)]
pub struct HashStateJs {
    hash: StreamingHash,
}

#[wasm_bindgen(js_class = HashState)]
impl HashStateJs {
    /// Absorbs the next part of the message.
    pub fn update(&mut self, data: &[u8]) {
        self.hash.update(data);
    }

    /// The hash of everything absorbed; the state is released.
    pub fn end(mut self) -> Vec<u8> {
        self.hash.finalize()
    }
}

impl HashStateJs {
    /// The state over `hash`.
    pub fn new(hash: StreamingHash) -> Self {
        Self { hash }
    }
}
