use crate::oids;
use crate::signature_level::SignatureLevel;

/// How [`CadesSigner`](crate::CadesSigner) signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CadesOptions {
    /// The hash of the data and of the signed attributes: [`oids::DSTU7564_256`] (default) or [`oids::GOST34311`].
    pub hash_oid: String,
    /// Leave the data out of the signature (ASiC-S, a .p7s next to the file).
    pub is_detached: bool,
    /// B, T (signatureTimeStampToken) or LT (CAdES-X Long).
    pub level: SignatureLevel,
    /// Add the signingTime signed attribute (default).
    pub has_signing_time: bool,
    /// Add a contentTimeStamp signed attribute over the data.
    pub has_content_time_stamp: bool,
}

impl Default for CadesOptions {
    fn default() -> Self {
        Self {
            hash_oid: oids::DSTU7564_256.to_owned(),
            is_detached: false,
            level: SignatureLevel::B,
            has_signing_time: true,
            has_content_time_stamp: false,
        }
    }
}
