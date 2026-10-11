/// A signature level: `UA_SIGNATURE_LEVEL_B`, `_T` or `_LT`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaSignatureLevel(pub u32);

/// The basic signature.
pub const UA_SIGNATURE_LEVEL_B: UaSignatureLevel = UaSignatureLevel(0);

/// With a signature time-stamp.
pub const UA_SIGNATURE_LEVEL_T: UaSignatureLevel = UaSignatureLevel(1);

/// With the CA certificates and OCSP responses: XAdES-B-LT, CAdES-X Long.
pub const UA_SIGNATURE_LEVEL_LT: UaSignatureLevel = UaSignatureLevel(2);
