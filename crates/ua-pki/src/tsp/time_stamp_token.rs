use num_bigint::BigInt;
use time::OffsetDateTime;
use ua_der::{Asn1Node, tag};

use crate::algorithms;
use crate::cms::{SignedData, SignerInfo, cms_verifier};
use crate::errors::TimeStampError;
use crate::oids;
use crate::time_text;
use crate::validation::VerificationReport;
use crate::x509::Certificate;

/// The position of the optional TSTInfo fields (after version, policy, messageImprint, serialNumber, genTime).
const FIRST_OPTIONAL_FIELD: usize = 5;

/// An RFC 3161 time-stamp token: CMS SignedData whose content is a DER TSTInfo (docs/signature-formats.md,
/// section 6). The message imprint is the hash of what was time-stamped, not reversed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeStampToken {
    cms: SignedData,
    policy: String,
    imprint_algorithm: String,
    imprint: Vec<u8>,
    serial_number: BigInt,
    gen_time: OffsetDateTime,
    nonce: Option<BigInt>,
}

impl TimeStampToken {
    /// Parses a token (DER, or PEM / base64 of it).
    pub fn load(data: &[u8]) -> Result<Self, TimeStampError> {
        Self::from_signed_data(SignedData::load(data)?)
    }

    /// Reads the TSTInfo of a CMS SignedData.
    pub fn from_signed_data(cms: SignedData) -> Result<Self, TimeStampError> {
        if cms.content_type() != oids::TST_INFO {
            return Err(TimeStampError::NotTstInfo);
        }
        let content = cms.content().ok_or(TimeStampError::NotTstInfo)?;
        if cms.signer_infos().len() != 1 {
            return Err(TimeStampError::SignerCount {
                count: cms.signer_infos().len(),
            });
        }
        // TSTInfo ::= SEQUENCE { version, policy, messageImprint, serialNumber, genTime, accuracy OPTIONAL,
        //                        ordering DEFAULT FALSE, nonce OPTIONAL, tsa [0] OPTIONAL, extensions [1] OPTIONAL }
        let info = Asn1Node::parse(content)?.expect_tag(tag::SEQUENCE)?;
        let fields = info.children()?;
        let imprint = info.child(2)?;
        // The last INTEGER among the optional fields is the nonce (accuracy is a SEQUENCE, ordering a BOOLEAN).
        let nonce = fields
            .iter()
            .skip(FIRST_OPTIONAL_FIELD)
            .rev()
            .find(|field| field.has_tag(tag::INTEGER));
        let nonce = match nonce {
            Some(nonce) => Some(nonce.to_integer()?),
            None => None,
        };
        Ok(Self {
            policy: info.child(1)?.to_oid()?,
            imprint_algorithm: imprint.child(0)?.child(0)?.to_oid()?,
            imprint: imprint.child(1)?.to_octet_string()?,
            serial_number: info.child(3)?.to_integer()?,
            gen_time: info.child(4)?.to_time()?,
            nonce,
            cms,
        })
    }

    /// The CMS SignedData.
    pub fn cms(&self) -> &SignedData {
        &self.cms
    }

    /// The DER token.
    pub fn encoded(&self) -> &[u8] {
        self.cms.encoded()
    }

    /// The single signer (the time-stamping service).
    pub fn signer(&self) -> &SignerInfo {
        &self.cms.signer_infos()[0]
    }

    /// The policy OID.
    pub fn policy(&self) -> &str {
        &self.policy
    }

    /// The message imprint's hash OID.
    pub fn imprint_algorithm(&self) -> &str {
        &self.imprint_algorithm
    }

    /// The message imprint: the hash of what was time-stamped.
    pub fn imprint(&self) -> &[u8] {
        &self.imprint
    }

    /// The token's serial number.
    pub fn serial_number(&self) -> &BigInt {
        &self.serial_number
    }

    /// The time of the time-stamp.
    pub fn gen_time(&self) -> OffsetDateTime {
        self.gen_time
    }

    /// The nonce of the request, when the token carries one.
    pub fn nonce(&self) -> Option<&BigInt> {
        self.nonce.as_ref()
    }

    /// True when the imprint is the hash of `covered` by the imprint's algorithm.
    pub fn covers(&self, covered: &[u8]) -> bool {
        algorithms::is_supported_hash(&self.imprint_algorithm)
            && algorithms::hash(&self.imprint_algorithm, covered, None).is_ok_and(|hash| hash == self.imprint)
    }

    /// The time-stamping service's certificate: in the token, else among `known`.
    pub fn find_signer_certificate(&self, known: &[Certificate]) -> Option<Certificate> {
        self.cms.find_certificate(self.signer(), known)
    }

    /// Verifies the token over `covered`: the imprint, the CMS signer and the extended key usage of the service
    /// certificate. Returns the service certificate, or none when it was not found: the token's signature then stays
    /// unverified, which is a warning — the token must not be relied on, but the signature it stamps is not wrong.
    pub fn verify(
        &self,
        covered: &[u8],
        known: &[Certificate],
        report: &mut VerificationReport,
        name: &str,
    ) -> Option<Certificate> {
        let covers = self.covers(covered);
        let details = if covers {
            format!(
                "{} imprint matches, time {} UTC",
                algorithms::hash_name(&self.imprint_algorithm),
                time_text::format_seconds(self.gen_time)
            )
        } else {
            "the time-stamp covers other data".to_owned()
        };
        report.check(&format!("{name}: imprint"), covers, &details);

        let service_check = format!("{name}: service certificate");
        let Some(authority) = self.find_signer_certificate(known) else {
            let details = format!(
                "the certificate of the time-stamping service ({}) is not available, so the time-stamp is not verified",
                self.signer()
            );
            report.warn(&service_check, &details);
            return None;
        };
        let Some(content) = self.cms.content() else {
            unreachable!("a time-stamp token is read only with its TSTInfo");
        };
        cms_verifier::verify_signer(self.signer(), &authority, oids::TST_INFO, content, report, name);
        if !authority
            .extended_key_usage()
            .iter()
            .any(|purpose| purpose == oids::KEY_PURPOSE_TIME_STAMPING)
        {
            let details = format!("'{}' has no timeStamping extended key usage", authority.subject());
            report.warn(&service_check, &details);
        }
        Some(authority)
    }
}
