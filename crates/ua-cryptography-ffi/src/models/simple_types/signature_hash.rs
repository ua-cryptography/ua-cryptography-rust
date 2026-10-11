use ua_cryptography_pki::oids;

use crate::errors::OperationFailure;

/// The hash a DSTU 4145 signature of the PKI is made over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureHash {
    /// DSTU 7564-256 (Kupyna), the hash of the current national PKI.
    Dstu7564,
    /// GOST 34.311-95 with the DKE of the key.
    Gost34311,
}

impl SignatureHash {
    /// The hash named as `ua-sign --hash` names it: dstu7564 or gost34311.
    pub fn parse(name: &str) -> Result<Self, OperationFailure> {
        match name.to_lowercase().as_str() {
            "dstu7564" => Ok(Self::Dstu7564),
            "gost34311" => Ok(Self::Gost34311),
            _ => Err(OperationFailure::invalid_argument(format!(
                "Unknown hash \"{name}\": dstu7564 or gost34311."
            ))),
        }
    }

    /// The OID of the hash.
    pub fn oid(self) -> &'static str {
        match self {
            Self::Dstu7564 => oids::DSTU7564_256,
            Self::Gost34311 => oids::GOST34311,
        }
    }
}
