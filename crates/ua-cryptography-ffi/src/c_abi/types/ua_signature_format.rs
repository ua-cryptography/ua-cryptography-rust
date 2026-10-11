/// A signature format: `UA_SIGNATURE_FORMAT_CADES`, `_XADES`, `_ASIC_S` or `_ASIC_E`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaSignatureFormat(pub u32);

/// CMS SignedData (.p7s), enveloped or detached; one file.
pub const UA_SIGNATURE_FORMAT_CADES: UaSignatureFormat = UaSignatureFormat(0);

/// A detached XML signature with one reference per file (.xml).
pub const UA_SIGNATURE_FORMAT_XADES: UaSignatureFormat = UaSignatureFormat(1);

/// A ZIP container with the file and a detached CAdES (.asics); one file.
pub const UA_SIGNATURE_FORMAT_ASIC_S: UaSignatureFormat = UaSignatureFormat(2);

/// A ZIP container with the files and a XAdES signature (.asice).
pub const UA_SIGNATURE_FORMAT_ASIC_E: UaSignatureFormat = UaSignatureFormat(3);
