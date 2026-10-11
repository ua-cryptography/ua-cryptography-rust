/// How a call ended. On anything but `UA_STATUS_OK`, the call's `error_message` holds the refusal in UTF-8.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UaStatus {
    /// Done; the outputs are written.
    Ok = 0,
    /// An argument is NULL, not UTF-8, of a wrong length, or a name or number the library does not know.
    InvalidArgument = 1,
    /// A key store, certificate or signature does not parse.
    UnreadableInput = 2,
    /// The key store or its key does not open with the password.
    WrongPassword = 3,
    /// An authenticated ciphertext or a wrapped key is not the one tagged.
    AuthenticationFailed = 4,
    /// A time-stamping, OCSP or certificate download service failed.
    ServiceFailure = 5,
    /// A defect of the library: the call panicked; the message says no more.
    Internal = 6,
}
