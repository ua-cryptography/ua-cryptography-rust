//! `ua_cryptography` for JavaScript, the npm package `ua-cryptography`: the algorithms, key stores, signing and
//! verification of `ua-cryptography-operations` behind `wasm-bindgen`, for browsers and Node.js.
//!
//! - [`js_exports`] — outbound: the functions and classes the page calls; `signOnline` and `verifyOnline` are async.
//! - [`js_imports`] — inbound: `fetch`, the module's one way to the PKI services.
//! - [`service_answers`] — what the services answered, behind the synchronous service traits of
//!   `ua-cryptography-pki`; the async operations fetch between runs of the synchronous ones.
//!
//! The asynchrony stays in this crate: `ua-cryptography-pki` and `ua-cryptography-operations` ask their services
//! synchronously, and the native builds answer them over sockets.

#![forbid(unsafe_code)]

mod js_exports;
mod js_imports;
mod service_answers;
