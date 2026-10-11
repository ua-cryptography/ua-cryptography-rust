use time::OffsetDateTime;

use crate::services::{CertificateSource, OcspService};
use crate::x509::Certificate;

/// What the verifier may rely on besides the signature itself.
#[derive(Clone, Default)]
pub struct ValidationOptions<'a> {
    /// Trusted roots (e.g. the ЦЗО certificates). When empty, the chain is built but trust is reported as a warning.
    pub trust_anchors: Vec<Certificate>,
    /// Certificates that may complete chains (CA certificates kept locally).
    pub extra_certificates: Vec<Certificate>,
    /// Asked when the signature carries no revocation data for a certificate; none keeps verification offline.
    pub online_ocsp: Option<&'a dyn OcspService>,
    /// Used to download missing CA certificates by authorityInfoAccess; none keeps verification offline.
    pub downloads: Option<&'a dyn CertificateSource>,
    /// "Now" for a signature without times and for online OCSP answers; none reads the system clock.
    pub current_time: Option<OffsetDateTime>,
}

impl ValidationOptions<'_> {
    /// [`current_time`](Self::current_time), or the system clock.
    pub fn now(&self) -> OffsetDateTime {
        match self.current_time {
            Some(time) => time,
            None => OffsetDateTime::now_utc(),
        }
    }
}
