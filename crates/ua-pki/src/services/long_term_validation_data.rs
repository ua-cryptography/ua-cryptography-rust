use crate::errors::SigningError;
use crate::ocsp::{OcspCertificateStatus, OcspResponse};
use crate::services::{CertificateSource, OcspService};
use crate::signing_key::SigningKey;
use crate::validation::certificate_path_validator::{self, short};
use crate::x509::Certificate;

/// What a long-term signature (CAdES-X Long, XAdES-B-LT) carries so that it can be validated later without the
/// network: the certificates of the signer's chain and of the services, and "good" OCSP responses for every
/// certificate below the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongTermValidationData {
    /// The signer's path: signer, CAs, root.
    pub chain: Vec<Certificate>,
    /// One "good" response per certificate below the root, the signer's first.
    pub responses: Vec<OcspResponse>,
    /// The CA certificates above the signer, followed by the OCSP responder certificates.
    pub certificates: Vec<Certificate>,
}

impl LongTermValidationData {
    /// Builds the signer's path (downloading missing CA certificates when `downloads` is given) and asks `ocsp` about
    /// every certificate below the root. Refuses when the path is incomplete or a response is missing, unsigned or
    /// not "good".
    pub fn collect(
        signer: &SigningKey,
        extra: &[Certificate],
        ocsp: &dyn OcspService,
        downloads: Option<&dyn CertificateSource>,
        hash_oid: &str,
    ) -> Result<Self, SigningError> {
        let pool: Vec<Certificate> = signer.chain().iter().chain(extra).cloned().collect();
        let chain = certificate_path_validator::build_chain(signer.certificate(), &pool, &[], downloads);
        let top = &chain[chain.len() - 1];
        if !(top.is_self_issued() && top.is_signed_by(top)) {
            return Err(SigningError::IncompletePath { top: short(top) });
        }

        let mut responses = Vec::new();
        let mut certificates: Vec<Certificate> = chain[1..].to_vec();
        for link in chain.windows(2) {
            let (certificate, issuer) = (&link[0], &link[1]);
            let subject = short(certificate);
            let response =
                ocsp.find_response(certificate, issuer, hash_oid)?
                    .ok_or_else(|| SigningError::NoOcspResponder {
                        subject: subject.clone(),
                    })?;
            let status = response
                .find(certificate, issuer)
                .map(|single| single.status)
                .ok_or_else(|| SigningError::ResponseNotCovering {
                    subject: subject.clone(),
                })?;
            let known: Vec<Certificate> = certificates.iter().chain(&chain).cloned().collect();
            let responder = response
                .find_responder(&known)
                .ok_or_else(|| SigningError::ResponderUnavailable {
                    subject: subject.clone(),
                })?;
            if !response.is_signed_by(&responder) {
                return Err(SigningError::ResponseNotSigned { subject });
            }
            if status != OcspCertificateStatus::Good {
                return Err(SigningError::CertificateNotGood { subject, status });
            }
            responses.push(response);
            if !certificates.contains(&responder) && &responder != signer.certificate() {
                certificates.push(responder);
            }
        }
        Ok(Self {
            chain,
            responses,
            certificates,
        })
    }
}
