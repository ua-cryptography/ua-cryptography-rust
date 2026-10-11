/// Signature levels common to CAdES and XAdES.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureLevel {
    /// Basic: the signed attributes / signed properties only.
    B,
    /// B and a time-stamp over the signature value.
    T,
    /// T and the certificates and OCSP responses needed for long-term validation: XAdES-B-LT, and CAdES-X Long (with the
    /// complete certificate and revocation references, as Ukrainian qualified tools write it).
    LT,
}
