//! The C ABI: `#[repr(C)]` types, the marshalling of pointers into the operations' inputs and outputs, and the
//! `extern "C"` functions. `unsafe` code lives in this module only: every pointer is read in `marshalling`.
#![allow(unsafe_code)]

mod call_guard;
mod exports;
mod marshalling;
mod types;
