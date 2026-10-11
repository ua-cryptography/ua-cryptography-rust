/// What kind of refusal ended an operation: the bindings turn it into a status code or a JavaScript error name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// An argument is missing, malformed or out of range: a key length, an unknown curve, a format option.
    InvalidArgument,
    /// An input does not parse: a key store, a certificate or a signature.
    UnreadableInput,
    /// The key store or its key does not open with the password.
    WrongPassword,
    /// An authenticated ciphertext or a wrapped key is not the one tagged.
    AuthenticationFailed,
    /// A time-stamping, OCSP or certificate download service failed or refused.
    ServiceFailure,
}
