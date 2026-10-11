use num_bigint::BigInt;
use time::OffsetDateTime;

use crate::algorithms;
use crate::ocsp::OcspCertificateStatus;
use crate::x509::Certificate;

/// A SingleResponse: the certificate identifier (CertID), its status and the validity interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcspSingleResponse {
    /// The CertID hash algorithm OID.
    pub hash_algorithm: String,
    /// The hash of the issuer's DER name.
    pub issuer_name_hash: Vec<u8>,
    /// The hash of the issuer's subjectPublicKey bits.
    pub issuer_key_hash: Vec<u8>,
    /// The certificate's serial number.
    pub serial_number: BigInt,
    /// What the responder says.
    pub status: OcspCertificateStatus,
    /// thisUpdate.
    pub this_update: OffsetDateTime,
    /// nextUpdate, when given.
    pub next_update: Option<OffsetDateTime>,
    /// revocationTime of a revoked certificate.
    pub revocation_time: Option<OffsetDateTime>,
}

impl OcspSingleResponse {
    /// True when the CertID names `certificate` issued by `issuer`. An issuerKeyHash of zeros (the "Дія" responder
    /// sends one) is matched by the serial number and the name hash alone: the response must still be signed by the
    /// issuer or by a responder the issuer certified, which binds it to the issuer's key.
    pub fn matches(&self, certificate: &Certificate, issuer: &Certificate) -> bool {
        &self.serial_number == certificate.serial_number()
            && algorithms::is_supported_hash(&self.hash_algorithm)
            && hash_equals(&self.hash_algorithm, issuer.subject().encoded(), &self.issuer_name_hash)
            && (self.has_zero_key_hash()
                || hash_equals(&self.hash_algorithm, issuer.public_key_bits(), &self.issuer_key_hash))
    }

    fn has_zero_key_hash(&self) -> bool {
        !self.issuer_key_hash.is_empty() && self.issuer_key_hash.iter().all(|&byte| byte == 0)
    }
}

fn hash_equals(hash_oid: &str, data: &[u8], expected: &[u8]) -> bool {
    algorithms::hash(hash_oid, data, None).is_ok_and(|hash| hash == expected)
}
