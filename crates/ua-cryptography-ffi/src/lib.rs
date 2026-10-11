//! The algorithms and formats of this workspace behind a C ABI: the `extern "C"` functions of
//! `include/ua_cryptography.h` over the operations of `ua-cryptography-operations`.
//!
//! - `c_abi`: the `#[repr(C)]` types, the marshalling of pointers, the `extern "C"` functions.
//! - `service_clients`: the HTTP clients of the time-stamping, OCSP and caIssuers services.

#![deny(unsafe_code)]

mod c_abi;
mod service_clients;
