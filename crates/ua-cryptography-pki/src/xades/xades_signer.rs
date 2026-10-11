use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand_core::{OsRng, RngCore};
use time::OffsetDateTime;
use ua_cryptography_xml_c14n::{Algorithm, DocumentText};

use crate::algorithms;
use crate::errors::SigningError;
use crate::signature_level::SignatureLevel;
use crate::signature_services::SignatureServices;
use crate::signing_key::SigningKey;
use crate::time_text;
use crate::x509::Certificate;
use crate::xades::xades_signature::DS_DECLARATION;
use crate::xades::xml_element::XmlElement;
use crate::xades::{SignedFile, XadesSignature, mime_type_of, uri_escape};
use crate::xml_namespaces;

/// The random bytes of a signature Id.
const ID_BYTES: usize = 8;
/// The namespace declaration of the `xades` prefix.
const XADES_DECLARATION: &str = "xmlns:xades";

/// Creates detached XAdES signatures (ETSI EN 319 132) in the shape of Ukrainian qualified signature tools
/// (docs/signature-formats.md, section 7): one ds:Reference per file, a reference to the signed properties, exclusive
/// canonicalization, the signer's certificate in ds:KeyInfo, and for higher levels a signature time-stamp,
/// certificate values and OCSP values.
#[derive(Clone)]
pub struct XadesSigner<'a> {
    signer: SigningKey,
    services: SignatureServices<'a>,
}

/// What a signature document is built from, filled step by step.
struct SignatureParts {
    id: String,
    digest_method: &'static str,
    signature_method: &'static str,
    references: Vec<(String, String)>,
    certificate: String,
    signing_time: String,
    certificate_digest: String,
    mime_types: Vec<&'static str>,
    properties_digest: String,
    signature_value: String,
    unsigned: Option<UnsignedParts>,
}

/// The unsigned signature properties: the time-stamp and, for level LT, the values.
struct UnsignedParts {
    time_stamp: String,
    long_term_values: Option<LongTermValues>,
}

/// CertificateValues and OCSPValues, base64.
struct LongTermValues {
    certificates: Vec<String>,
    ocsp_responses: Vec<String>,
}

impl<'a> XadesSigner<'a> {
    /// A signer with `signer`'s key; `services` are needed for levels T and LT.
    pub fn new(signer: SigningKey, services: SignatureServices<'a>) -> Self {
        Self { signer, services }
    }

    /// A ds:Signature over `files`, hashed with `hash_oid` ([`oids::DSTU7564_256`](crate::oids::DSTU7564_256) or
    /// [`oids::GOST34311`](crate::oids::GOST34311)), at `level`.
    pub fn sign(
        &self,
        files: &[SignedFile],
        hash_oid: &str,
        level: SignatureLevel,
    ) -> Result<XadesSignature, SigningError> {
        if files.is_empty() {
            return Err(SigningError::NothingToSign);
        }
        let mut parts = self.signed_parts(files, hash_oid)?;
        let properties = canonical_element(&parts, "SignedProperties");
        parts.properties_digest = BASE64.encode(self.hash(hash_oid, &properties)?);
        let signed_info = canonical_element(&parts, "SignedInfo");
        let signature = self.signer.key().sign_hash(&self.hash(hash_oid, &signed_info)?)?;
        parts.signature_value = BASE64.encode(signature);
        if level >= SignatureLevel::T {
            parts.unsigned = Some(self.unsigned_parts(&parts, hash_oid, level)?);
        }
        Ok(XadesSignature::new(parts.id.clone(), build_signature(&parts)))
    }

    /// The signature as bytes (UTF-8 XML with a declaration).
    pub fn sign_to_bytes(
        &self,
        files: &[SignedFile],
        hash_oid: &str,
        level: SignatureLevel,
    ) -> Result<Vec<u8>, SigningError> {
        Ok(self.sign(files, hash_oid, level)?.to_bytes())
    }

    fn signed_parts(&self, files: &[SignedFile], hash_oid: &str) -> Result<SignatureParts, SigningError> {
        let mut id_bytes = [0u8; ID_BYTES];
        OsRng.fill_bytes(&mut id_bytes);
        let mut references = Vec::new();
        for file in files {
            let uri = uri_escape::escape_file_name(&file.name);
            references.push((uri, BASE64.encode(self.hash(hash_oid, &file.content)?)));
        }
        let certificate = self.signer.certificate();
        Ok(SignatureParts {
            id: format!("S-{}", crate::x509::hex_upper(&id_bytes)),
            digest_method: algorithms::xml_digest_method(hash_oid)?,
            signature_method: algorithms::xml_signature_method(hash_oid)?,
            references,
            certificate: BASE64.encode(certificate.encoded()),
            // Whole seconds, as "Дія" and IIT write it.
            signing_time: time_text::format_xml_seconds(OffsetDateTime::now_utc()),
            certificate_digest: BASE64.encode(self.hash(hash_oid, certificate.encoded())?),
            mime_types: files.iter().map(|file| mime_type_of(&file.name)).collect(),
            properties_digest: String::new(),
            signature_value: String::new(),
            unsigned: None,
        })
    }

    fn unsigned_parts(
        &self,
        parts: &SignatureParts,
        hash_oid: &str,
        level: SignatureLevel,
    ) -> Result<UnsignedParts, SigningError> {
        let covered = canonical_element(parts, "SignatureValue");
        let hash = algorithms::hash(hash_oid, &covered, None)?;
        let token = self.services.require_time_stamps()?.get_token(&hash, hash_oid)?;
        let mut unsigned = UnsignedParts {
            time_stamp: BASE64.encode(token.encoded()),
            long_term_values: None,
        };
        if level < SignatureLevel::LT {
            return Ok(unsigned);
        }
        let data = self.services.collect_long_term_data(&self.signer, hash_oid)?;
        let mut certificates: Vec<Certificate> = data.certificates.clone();
        for certificate in token.cms().certificates() {
            if !certificates.contains(certificate) && certificate != self.signer.certificate() {
                certificates.push(certificate.clone());
            }
        }
        unsigned.long_term_values = Some(LongTermValues {
            certificates: certificates
                .iter()
                .map(|certificate: &Certificate| BASE64.encode(certificate.encoded()))
                .collect(),
            ocsp_responses: data
                .responses
                .iter()
                .map(|response| BASE64.encode(response.full_encoded()))
                .collect(),
        });
        Ok(unsigned)
    }

    fn hash(&self, hash_oid: &str, data: &[u8]) -> Result<Vec<u8>, SigningError> {
        Ok(algorithms::hash(hash_oid, data, self.signer.key().dke())?)
    }
}

// The exclusive canonical form of the first element named `local_name` of the signature built so far.
fn canonical_element(parts: &SignatureParts, local_name: &str) -> Vec<u8> {
    let text = build_signature(parts).to_text();
    let document_text = match DocumentText::decode(text.as_bytes()) {
        Ok(document_text) => document_text,
        Err(error) => unreachable!("the signature written must decode: {error}"),
    };
    let document = match document_text.parse() {
        Ok(document) => document,
        Err(error) => unreachable!("the signature written must parse: {error}"),
    };
    let Some(element) = document.descendants().find(|node| node.tag_name().name() == local_name) else {
        unreachable!("the signature written has a {local_name}");
    };
    ua_cryptography_xml_c14n::canonicalize(element, Algorithm::Exclusive, &[], None)
}

fn method(name: &str, algorithm: &str) -> XmlElement {
    XmlElement::new(name).with_attribute("Algorithm", algorithm)
}

// The ds:Signature element in the order and with the names C# XadesSigner writes.
fn build_signature(parts: &SignatureParts) -> XmlElement {
    let id = &parts.id;
    let exclusive = Algorithm::Exclusive.uri();
    let mut signed_info = XmlElement::new("ds:SignedInfo")
        .with_child(method("ds:CanonicalizationMethod", exclusive))
        .with_child(method("ds:SignatureMethod", parts.signature_method));
    for (index, (uri, digest)) in parts.references.iter().enumerate() {
        let reference = XmlElement::new("ds:Reference")
            .with_attribute("Id", &format!("{id}-Reference-{}", index + 1))
            .with_attribute("URI", uri)
            .with_child(method("ds:DigestMethod", parts.digest_method))
            .with_child(XmlElement::new("ds:DigestValue").with_text(digest));
        signed_info = signed_info.with_child(reference);
    }
    let properties_reference = XmlElement::new("ds:Reference")
        .with_attribute("Type", xml_namespaces::SIGNED_PROPERTIES_TYPE)
        .with_attribute("URI", &format!("#{id}-SignedProperties"))
        .with_child(XmlElement::new("ds:Transforms").with_child(method("ds:Transform", exclusive)))
        .with_child(method("ds:DigestMethod", parts.digest_method))
        .with_child(text_element("ds:DigestValue", &parts.properties_digest));
    signed_info = signed_info.with_child(properties_reference);

    let signature_value =
        text_element("ds:SignatureValue", &parts.signature_value).with_attribute("Id", &format!("{id}-SignatureValue"));
    let key_info = XmlElement::new("ds:KeyInfo").with_child(
        XmlElement::new("ds:X509Data").with_child(XmlElement::new("ds:X509Certificate").with_text(&parts.certificate)),
    );
    let mut qualifying = XmlElement::new("xades:QualifyingProperties")
        .with_attribute("Target", &format!("#{id}"))
        .with_attribute(XADES_DECLARATION, xml_namespaces::XADES)
        .with_child(build_signed_properties(parts));
    if let Some(unsigned) = &parts.unsigned {
        qualifying = qualifying.with_child(build_unsigned_properties(unsigned));
    }
    XmlElement::new("ds:Signature")
        .with_attribute("Id", id)
        .with_attribute(DS_DECLARATION, xml_namespaces::DS)
        .with_child(signed_info)
        .with_child(signature_value)
        .with_child(key_info)
        .with_child(XmlElement::new("ds:Object").with_child(qualifying))
}

fn build_signed_properties(parts: &SignatureParts) -> XmlElement {
    let id = &parts.id;
    let certificate_digest = XmlElement::new("xades:CertDigest")
        .with_child(method("ds:DigestMethod", parts.digest_method))
        .with_child(XmlElement::new("ds:DigestValue").with_text(&parts.certificate_digest));
    let signature_properties = XmlElement::new("xades:SignedSignatureProperties")
        .with_child(XmlElement::new("xades:SigningTime").with_text(&parts.signing_time))
        .with_child(
            XmlElement::new("xades:SigningCertificateV2")
                .with_child(XmlElement::new("xades:Cert").with_child(certificate_digest)),
        );
    let mut data_properties = XmlElement::new("xades:SignedDataObjectProperties");
    for (index, mime_type) in parts.mime_types.iter().enumerate() {
        let format = XmlElement::new("xades:DataObjectFormat")
            .with_attribute("ObjectReference", &format!("#{id}-Reference-{}", index + 1))
            .with_child(XmlElement::new("xades:MimeType").with_text(mime_type));
        data_properties = data_properties.with_child(format);
    }
    XmlElement::new("xades:SignedProperties")
        .with_attribute("Id", &format!("{id}-SignedProperties"))
        .with_child(signature_properties)
        .with_child(data_properties)
}

fn build_unsigned_properties(unsigned: &UnsignedParts) -> XmlElement {
    let time_stamp = XmlElement::new("xades:SignatureTimeStamp")
        .with_child(method("ds:CanonicalizationMethod", Algorithm::Exclusive.uri()))
        .with_child(XmlElement::new("xades:EncapsulatedTimeStamp").with_text(&unsigned.time_stamp));
    let mut properties = XmlElement::new("xades:UnsignedSignatureProperties").with_child(time_stamp);
    if let Some(long_term) = &unsigned.long_term_values {
        let mut values = XmlElement::new("xades:CertificateValues");
        for certificate in &long_term.certificates {
            values = values.with_child(XmlElement::new("xades:EncapsulatedX509Certificate").with_text(certificate));
        }
        let mut ocsp = XmlElement::new("xades:OCSPValues");
        for response in &long_term.ocsp_responses {
            ocsp = ocsp.with_child(XmlElement::new("xades:EncapsulatedOCSPValue").with_text(response));
        }
        properties = properties
            .with_child(values)
            .with_child(XmlElement::new("xades:RevocationValues").with_child(ocsp));
    }
    XmlElement::new("xades:UnsignedProperties").with_child(properties)
}

// An element with text, written empty while the text is not known yet.
fn text_element(name: &str, text: &str) -> XmlElement {
    let element = XmlElement::new(name);
    if text.is_empty() {
        element
    } else {
        element.with_text(text)
    }
}
