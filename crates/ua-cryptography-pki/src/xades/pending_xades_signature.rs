use crate::signature_level::SignatureLevel;
use crate::xades::xades_signer::SignatureParts;

/// A XAdES signature whose ds:SignedInfo and ds:SignatureValue are final, waiting for its unsigned properties (the
/// signature time-stamp of level T, the values of level LT): made by
/// [`XadesSigner::prepare`](crate::XadesSigner::prepare), finished by
/// [`XadesSigner::complete`](crate::XadesSigner::complete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingXadesSignature {
    pub(crate) parts: SignatureParts,
    pub(crate) hash_oid: String,
    pub(crate) level: SignatureLevel,
}
