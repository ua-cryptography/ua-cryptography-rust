//! The operations behind the C ABI (`ua-cryptography-ffi`) and the JavaScript bindings (`ua-cryptography-wasm`):
//! plain Rust, bytes in and a model or [`OperationFailure`] out — GOST 28147 and 34.311, DSTU 7564, DSTU 7624 with
//! its modes, DSTU 4145, JKS key stores, signing and verification of files.
//!
//! The operations reach no network: signing and verification take the PKI services from the binding, which knows
//! how its platform reaches them (sockets natively, `fetch` in the browser).

#![forbid(unsafe_code)]

mod errors;
pub mod models;
pub mod operations;
mod utils;

pub use errors::FailureKind;
pub use errors::OperationFailure;

pub use utils::to_json;
