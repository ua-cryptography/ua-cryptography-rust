use ua_cryptography_pki::{PendingCadesSignature, PendingXadesSignature};

/// A signature of a request whose value is final, waiting for its time-stamp and long-term values, in the format the
/// request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingSignature {
    /// CMS SignedData.
    Cades(PendingCadesSignature),
    /// A detached CAdES, packed into an ASiC-S container with its file.
    AsicS(PendingCadesSignature),
    /// A detached XML signature.
    Xades(PendingXadesSignature),
    /// A XAdES signature, packed into an ASiC-E container with its files.
    AsicE(PendingXadesSignature),
}
