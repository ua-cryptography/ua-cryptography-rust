//! One call across the C ABI: its refusal becomes a status and a message, and a panic never unwinds into C.

use std::panic::{self, AssertUnwindSafe};

use crate::c_abi::marshalling::into_buffer;
use crate::c_abi::types::{UaBuffer, UaStatus};
use ua_cryptography_operations::{FailureKind, OperationFailure};

/// What the caller reads of a panic: the details stay in the process's panic output.
const INTERNAL_MESSAGE: &str = "Internal error of ua_cryptography.";

/// Runs `call`; on a refusal or a panic writes the text to `error_message` (when not NULL) and returns the status.
///
/// # Safety
/// `error_message` is NULL or points to a writable `UaBuffer`.
pub unsafe fn run_call(error_message: *mut UaBuffer, call: impl FnOnce() -> Result<(), OperationFailure>) -> UaStatus {
    let (status, text) = match panic::catch_unwind(AssertUnwindSafe(call)) {
        Ok(Ok(())) => return UaStatus::Ok,
        Ok(Err(failure)) => (status_of(failure.kind), failure.message),
        Err(_) => (UaStatus::Internal, INTERNAL_MESSAGE.to_owned()),
    };
    if !error_message.is_null() {
        // SAFETY: the caller passes NULL or a writable UaBuffer.
        unsafe { error_message.write(into_buffer(text.into_bytes())) };
    }
    status
}

fn status_of(kind: FailureKind) -> UaStatus {
    match kind {
        FailureKind::InvalidArgument => UaStatus::InvalidArgument,
        FailureKind::UnreadableInput => UaStatus::UnreadableInput,
        FailureKind::WrongPassword => UaStatus::WrongPassword,
        FailureKind::AuthenticationFailed => UaStatus::AuthenticationFailed,
        FailureKind::ServiceFailure => UaStatus::ServiceFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::c_abi::marshalling::release_buffer;
    use std::ptr;

    fn read_message(message: UaBuffer) -> String {
        // SAFETY: a buffer the guard wrote, released once below.
        let text = unsafe { std::slice::from_raw_parts(message.data, message.len) }.to_vec();
        unsafe { release_buffer(message) };
        String::from_utf8(text).unwrap()
    }

    #[test]
    fn a_refusal_becomes_its_status_and_message() {
        let mut message = UaBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
        let status = unsafe {
            run_call(&mut message, || {
                Err(OperationFailure::new(FailureKind::WrongPassword, "Wrong password."))
            })
        };
        assert_eq!(status, UaStatus::WrongPassword);
        assert_eq!(read_message(message), "Wrong password.");
    }

    #[test]
    fn a_panic_does_not_cross_into_c() {
        let mut message = UaBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
        let status = unsafe { run_call(&mut message, || panic!("a defect")) };
        assert_eq!(status, UaStatus::Internal);
        assert_eq!(read_message(message), INTERNAL_MESSAGE);
    }

    #[test]
    fn a_null_message_is_allowed() {
        let status = unsafe { run_call(ptr::null_mut(), || Err(OperationFailure::invalid_argument("bad"))) };
        assert_eq!(status, UaStatus::InvalidArgument);
    }
}
