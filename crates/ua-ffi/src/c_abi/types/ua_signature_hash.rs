/// The hash of a PKI signature: `UA_SIGNATURE_HASH_DSTU7564` (DSTU 7564-256) or `UA_SIGNATURE_HASH_GOST34311`.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UaSignatureHash(pub u32);

/// DSTU 7564-256 (Kupyna), the hash of the current national PKI.
pub const UA_SIGNATURE_HASH_DSTU7564: UaSignatureHash = UaSignatureHash(0);

/// GOST 34.311-95 with the DKE of the key.
pub const UA_SIGNATURE_HASH_GOST34311: UaSignatureHash = UaSignatureHash(1);
