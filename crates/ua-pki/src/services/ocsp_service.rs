use crate::errors::ServiceError;
use crate::ocsp::OcspResponse;
use crate::x509::Certificate;

/// An OCSP service (RFC 6960).
pub trait OcspService {
    /// A response about `certificate` issued by `issuer`, its CertID hashed with `hash_oid`; none when no responder is
    /// known for the certificate.
    fn find_response(
        &self,
        certificate: &Certificate,
        issuer: &Certificate,
        hash_oid: &str,
    ) -> Result<Option<OcspResponse>, ServiceError>;
}
