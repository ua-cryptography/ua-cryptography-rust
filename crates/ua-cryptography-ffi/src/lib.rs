//! The algorithms and formats of this workspace behind a C ABI (native platforms) and JavaScript bindings
//! (`wasm32-unknown-unknown`).
//!
//! - [`operations`]: plain Rust, bytes in and a model or [`OperationFailure`] out — GOST 28147 and 34.311,
//!   DSTU 7564, DSTU 7624 with its modes, DSTU 4145, JKS key stores, signing and verification of files.
//! - `c_abi`: the `extern "C"` functions of `include/ua_cryptography.h` over the operations.
//! - `wasm_bindings`: the `#[wasm_bindgen]` functions of the npm package over the same operations.

#![deny(unsafe_code)]

mod errors;
pub mod models;
pub mod operations;
mod utils;

#[cfg(not(target_arch = "wasm32"))]
mod c_abi;
#[cfg(target_arch = "wasm32")]
mod wasm_bindings;

pub use errors::FailureKind;
pub use errors::OperationFailure;
