use crate::cades::CadesOptions;

/// A CAdES signature whose signed attributes and value are final, waiting for its unsigned attributes (the signature
/// time-stamp of level T, the values of level LT): made by [`CadesSigner::prepare`](crate::CadesSigner::prepare),
/// finished by [`CadesSigner::complete`](crate::CadesSigner::complete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCadesSignature {
    pub(crate) signed_attributes: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) encapsulated: Option<Vec<u8>>,
    pub(crate) options: CadesOptions,
}
