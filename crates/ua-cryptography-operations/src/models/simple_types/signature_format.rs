use crate::errors::OperationFailure;

/// The signature formats of the national PKI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureFormat {
    /// CMS SignedData (.p7s), enveloped or detached.
    Cades,
    /// A detached XML signature with one reference per file (.xml).
    Xades,
    /// A ZIP container with the file and a detached CAdES (.asics).
    AsicS,
    /// A ZIP container with the files and a XAdES signature (.asice).
    AsicE,
}

impl SignatureFormat {
    /// The format named as `ua-sign --format` names it: cades, xades, asic-s, asic-e.
    pub fn parse(name: &str) -> Result<Self, OperationFailure> {
        match name.to_lowercase().as_str() {
            "cades" => Ok(Self::Cades),
            "xades" => Ok(Self::Xades),
            "asic-s" => Ok(Self::AsicS),
            "asic-e" => Ok(Self::AsicE),
            _ => Err(OperationFailure::invalid_argument(format!(
                "Unknown signature format \"{name}\": cades, xades, asic-s or asic-e."
            ))),
        }
    }

    /// Whether the signature inside is CAdES: one file, detached or content time-stamped.
    pub fn is_cades(self) -> bool {
        matches!(self, Self::Cades | Self::AsicS)
    }
}
