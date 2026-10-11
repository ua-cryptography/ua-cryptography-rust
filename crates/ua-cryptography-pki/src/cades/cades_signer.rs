use time::OffsetDateTime;

use crate::algorithms;
use crate::cades::CadesOptions;
use crate::cms::cms_builder;
use crate::errors::SigningError;
use crate::oids;
use crate::services::LongTermValidationData;
use crate::signature_level::SignatureLevel;
use crate::signature_services::SignatureServices;
use crate::signing_key::SigningKey;
use crate::tsp::TimeStampToken;

/// The context tag of CrlOcspRef.ocspids and RevocationValues.ocspVals.
const OCSP_TAG: u8 = 1;

/// Creates CAdES signatures (ETSI EN 319 122) shaped like those of Ukrainian qualified signature tools
/// (docs/signature-formats.md, sections 9 and 10).
#[derive(Clone)]
pub struct CadesSigner<'a> {
    signer: SigningKey,
    services: SignatureServices<'a>,
}

impl<'a> CadesSigner<'a> {
    /// A signer with `signer`'s key; `services` are needed for levels T and LT and for a content time-stamp.
    pub fn new(signer: SigningKey, services: SignatureServices<'a>) -> Self {
        Self { signer, services }
    }

    /// A ContentInfo with SignedData over `data`.
    pub fn sign(&self, data: &[u8], options: &CadesOptions) -> Result<Vec<u8>, SigningError> {
        let hash_oid = options.hash_oid.as_str();
        let mut extra = Vec::new();
        if options.has_signing_time {
            let now = OffsetDateTime::now_utc();
            extra.push(cms_builder::attribute(
                oids::SIGNING_TIME,
                [ua_cryptography_der::x509_time(now)],
            ));
        }
        if options.has_content_time_stamp {
            let token = self.stamp(data, hash_oid)?;
            extra.push(cms_builder::attribute(oids::CONTENT_TIME_STAMP, [token.encoded()]));
        }

        let signed_attributes = cms_builder::signed_attributes(data, oids::DATA, &self.signer, hash_oid, &extra)?;
        let (mut signer_info, signature) = cms_builder::signer_info(&signed_attributes, &self.signer, hash_oid, &[])?;

        let mut unsigned = Vec::new();
        if options.level >= SignatureLevel::T {
            let token = self.stamp(&signature, hash_oid)?;
            unsigned.push(cms_builder::attribute(
                oids::SIGNATURE_TIME_STAMP_TOKEN,
                [token.encoded()],
            ));
        }
        if options.level >= SignatureLevel::LT {
            let data = self.services.collect_long_term_data(&self.signer, hash_oid)?;
            unsigned.extend(long_term_attributes(&data, hash_oid)?);
        }
        if !unsigned.is_empty() {
            let certificate = self.signer.certificate();
            signer_info =
                cms_builder::signer_info_with(&signed_attributes, &signature, certificate, hash_oid, &unsigned)?;
        }

        let encapsulated = if options.is_detached { None } else { Some(data) };
        let certificates = [self.signer.certificate().clone()];
        Ok(cms_builder::signed_data(
            &signer_info,
            hash_oid,
            oids::DATA,
            encapsulated,
            &certificates,
        ))
    }

    fn stamp(&self, covered: &[u8], hash_oid: &str) -> Result<TimeStampToken, SigningError> {
        let hash = algorithms::hash(hash_oid, covered, None)?;
        Ok(self.services.require_time_stamps()?.get_token(&hash, hash_oid)?)
    }
}

/// CAdES-C references and CAdES-X Long values: completeCertificateRefs and certValues over the CA and responder
/// certificates, completeRevocationRefs and revocationValues over the OCSP responses. References hash with the
/// signature's hash algorithm.
fn long_term_attributes(data: &LongTermValidationData, hash_oid: &str) -> Result<Vec<Vec<u8>>, SigningError> {
    let other_hash = |encoded: &[u8]| -> Result<Vec<u8>, SigningError> {
        let hash = algorithms::hash(hash_oid, encoded, None)?;
        Ok(ua_cryptography_der::sequence([
            ua_cryptography_der::algorithm_identifier(hash_oid),
            ua_cryptography_der::octet_string(&hash),
        ]))
    };
    let mut certificate_refs = Vec::new();
    for certificate in &data.certificates {
        certificate_refs.push(ua_cryptography_der::sequence([other_hash(certificate.encoded())?]));
    }
    let mut ocsp_ids = Vec::new();
    for response in &data.responses {
        let identifier = ua_cryptography_der::sequence([
            response.responder_id_encoded().to_vec(),
            ua_cryptography_der::generalized_time(response.produced_at()),
        ]);
        ocsp_ids.push(ua_cryptography_der::sequence([
            identifier,
            other_hash(response.basic_encoded())?,
        ]));
    }
    let revocation_refs =
        ua_cryptography_der::sequence([ua_cryptography_der::sequence([ua_cryptography_der::explicit(
            OCSP_TAG,
            &ua_cryptography_der::sequence([ua_cryptography_der::sequence(ocsp_ids)]),
        )])]);
    let certificate_values =
        ua_cryptography_der::sequence(data.certificates.iter().map(|certificate| certificate.encoded()));
    let ocsp_values = ua_cryptography_der::sequence(data.responses.iter().map(|response| response.basic_encoded()));
    let revocation_values = ua_cryptography_der::sequence([ua_cryptography_der::explicit(OCSP_TAG, &ocsp_values)]);
    Ok(vec![
        cms_builder::attribute(
            oids::CERTIFICATE_REFS,
            [ua_cryptography_der::sequence(certificate_refs)],
        ),
        cms_builder::attribute(oids::REVOCATION_REFS, [revocation_refs]),
        cms_builder::attribute(oids::CERT_VALUES, [certificate_values]),
        cms_builder::attribute(oids::REVOCATION_VALUES, [revocation_values]),
    ])
}
