use crate::errors::SigningError;
use crate::services::{CertificateSource, LongTermValidationData, OcspService, TimeStampService};
use crate::signing_key::SigningKey;
use crate::x509::Certificate;

/// The online services a signer uses for levels T and LT.
#[derive(Clone, Default)]
pub struct SignatureServices<'a> {
    /// The time-stamping service (required for T and LT).
    pub time_stamps: Option<&'a dyn TimeStampService>,
    /// The OCSP service (required for LT).
    pub ocsp: Option<&'a dyn OcspService>,
    /// Downloads missing CA certificates (optional).
    pub downloads: Option<&'a dyn CertificateSource>,
    /// CA certificates kept locally that complete the signer's chain.
    pub extra_certificates: Vec<Certificate>,
}

impl<'a> SignatureServices<'a> {
    /// The time-stamping service, or the refusal of levels T and LT without one.
    pub(crate) fn require_time_stamps(&self) -> Result<&'a dyn TimeStampService, SigningError> {
        self.time_stamps.ok_or(SigningError::NoTimeStampService)
    }

    /// The long-term validation data of `signer`, or the refusal of level LT without an OCSP service.
    pub(crate) fn collect_long_term_data(
        &self,
        signer: &SigningKey,
        hash_oid: &str,
    ) -> Result<LongTermValidationData, SigningError> {
        let ocsp = self.ocsp.ok_or(SigningError::NoOcspService)?;
        LongTermValidationData::collect(signer, &self.extra_certificates, ocsp, self.downloads, hash_oid)
    }
}
