use ua_der::{Asn1Node, tag};

use crate::cms::SignerInfo;
use crate::errors::CmsError;
use crate::oids;
use crate::x509::Certificate;

/// The context tag of ContentInfo.content, of encapContentInfo.eContent and of SignedData.certificates.
const CONTENT_TAG: u8 = 0;
/// The context tag of SignedData.certificates.
const CERTIFICATES_TAG: u8 = 0;
/// The context tag of SignedData.crls.
const REVOCATION_INFO_TAG: u8 = 1;
/// The position of SignedData.certificates when present (after version, digestAlgorithms, encapContentInfo).
const FIRST_OPTIONAL_FIELD: usize = 3;

/// ContentInfo with SignedData (RFC 5652, 5.1): the encapsulated content, the certificates and the signers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedData {
    encoded: Vec<u8>,
    version: i32,
    digest_algorithms: Vec<String>,
    content_type: String,
    content: Option<Vec<u8>>,
    certificates: Vec<Certificate>,
    signer_infos: Vec<SignerInfo>,
}

impl SignedData {
    /// Parses DER/BER, or PEM / bare base64 of it.
    pub fn load(data: &[u8]) -> Result<Self, CmsError> {
        let encoded = ua_der::decode_pem(data, "CMS")?;
        let content_info = Asn1Node::parse(&encoded)?.expect_tag(tag::SEQUENCE)?;
        let content_type = content_info.child(0)?.to_oid()?;
        if content_type != oids::SIGNED_DATA {
            return Err(CmsError::NotSignedData { content_type });
        }
        let signed_data = content_info
            .child(1)?
            .expect_tag(tag::context_constructed(CONTENT_TAG))?
            .child(0)?
            .expect_tag(tag::SEQUENCE)?;
        let fields = signed_data.children()?;
        let field = |index: usize| signed_data.child(index);

        let encapsulated = field(2)?;
        let content = read_encapsulated_content(&encapsulated)?;
        let mut index = FIRST_OPTIONAL_FIELD;
        let mut certificates = Vec::new();
        if field(index)?.is_context(CERTIFICATES_TAG) {
            certificates = read_certificates(&field(index)?)?;
            index += 1;
        }
        if fields
            .get(index)
            .is_some_and(|node| node.is_context(REVOCATION_INFO_TAG))
        {
            index += 1;
        }
        let signer_infos = field(index)?
            .expect_tag(tag::SET)?
            .children()?
            .iter()
            .map(SignerInfo::from_asn1)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            version: field(0)?.to_i32()?,
            digest_algorithms: field(1)?
                .children()?
                .iter()
                .map(|algorithm| algorithm.child(0).and_then(|oid| oid.to_oid()))
                .collect::<Result<Vec<_>, _>>()?,
            content_type: encapsulated.child(0)?.to_oid()?,
            content,
            certificates,
            signer_infos,
            encoded,
        })
    }

    /// The DER (or BER) ContentInfo as received.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// The SignedData version.
    pub fn version(&self) -> i32 {
        self.version
    }

    /// The digestAlgorithms OIDs.
    pub fn digest_algorithms(&self) -> &[String] {
        &self.digest_algorithms
    }

    /// eContentType: [`oids::DATA`] for signatures, [`oids::TST_INFO`] for time-stamp tokens.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// The encapsulated content, or none for a detached signature.
    pub fn content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    /// The embedded certificates.
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// The signers.
    pub fn signer_infos(&self) -> &[SignerInfo] {
        &self.signer_infos
    }

    /// The certificate named by the signer identifier among the embedded ones and `known`.
    pub fn find_certificate(&self, signer: &SignerInfo, known: &[Certificate]) -> Option<Certificate> {
        self.certificates
            .iter()
            .chain(known)
            .find(|certificate| signer.identifies(certificate))
            .cloned()
    }
}

// EncapsulatedContentInfo ::= SEQUENCE { eContentType, eContent [0] EXPLICIT OCTET STRING OPTIONAL }
fn read_encapsulated_content(encapsulated: &Asn1Node<'_>) -> Result<Option<Vec<u8>>, CmsError> {
    let Some(explicit) = encapsulated.children()?.get(1).copied() else {
        return Ok(None);
    };
    let content = explicit.expect_tag(tag::context_constructed(CONTENT_TAG))?.child(0)?;
    Ok(Some(content.to_octet_string()?))
}

// Other CertificateChoices (attribute certificates and the like) are skipped.
fn read_certificates(choices: &Asn1Node<'_>) -> Result<Vec<Certificate>, CmsError> {
    let mut certificates = Vec::new();
    for choice in choices.children()? {
        if choice.has_tag(tag::SEQUENCE) {
            certificates.push(Certificate::load(choice.encoded())?);
        }
    }
    Ok(certificates)
}
