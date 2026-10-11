//! Verifies XAdES signatures (docs/signature-formats.md, section 7): every ds:Reference, the signed properties and
//! the signing certificate they name, the DSTU 4145 signature over the canonical ds:SignedInfo, the signature
//! time-stamp, the certificate and OCSP values, and the certificate path.
//!
//! Against signature wrapping, same-document references must resolve to exactly one element, and the signed
//! properties are read only from the element the signature actually covers, inside this ds:Signature.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use roxmltree::{Document, Node};
use ua_xml_c14n::Algorithm;

use crate::algorithms;
use crate::errors::{AlgorithmError, CertificateError, KeyError, OcspError, TimeStampError};
use crate::ocsp::OcspResponse;
use crate::time_text;
use crate::tsp::TimeStampToken;
use crate::validation::{
    CheckStatus, SignedObject, TimeStampDetails, ValidationOptions, VerificationReport, certificate_path_validator,
};
use crate::x509::Certificate;
use crate::xades::uri_escape;
use crate::xml_namespaces::{DS, ENVELOPED_SIGNATURE, XADES, XADES_141};

/// The name of a same-document reference to the whole document.
const DOCUMENT_REFERENCE: &str = "(document)";
/// The check names of the signature time-stamp.
const SIGNATURE_TIME_STAMP: &str = "signature time-stamp";
/// The prefix-list element of exclusive canonicalization.
const INCLUSIVE_NAMESPACES: &str = "InclusiveNamespaces";
/// The prefix-list attribute.
const PREFIX_LIST: &str = "PrefixList";

/// Verifies every ds:Signature of `document`. `resolve` returns the content of an external reference (a file name,
/// already URI-unescaped), or none when it is not available.
pub fn verify(
    document: &Document<'_>,
    resolve: &dyn Fn(&str) -> Option<Vec<u8>>,
    options: &ValidationOptions<'_>,
) -> Vec<VerificationReport> {
    let mut reports = Vec::new();
    for signature in document.descendants().filter(|node| is_element(node, DS, "Signature")) {
        let id = attribute_or_empty(&signature, "Id");
        let title = if id.is_empty() {
            "XAdES signature".to_owned()
        } else {
            format!("XAdES signature {id}")
        };
        let mut report = VerificationReport::new(&title);
        let context = SignatureContext {
            document,
            signature,
            resolve,
            options,
        };
        if let Err(error) = verify_signature(&context, &mut report) {
            report.fail("structure", &error.to_string());
        }
        reports.push(report);
    }
    reports
}

/// The names of the external files the signatures of `document` reference, URI-unescaped, in document order.
pub fn external_references(document: &Document<'_>) -> Vec<String> {
    let mut names = Vec::new();
    for signature in document.descendants().filter(|node| is_element(node, DS, "Signature")) {
        for signed_info in children(&signature, DS, "SignedInfo") {
            for reference in children(&signed_info, DS, "Reference") {
                let uri = attribute_or_empty(&reference, "URI");
                if !uri.is_empty() && !uri.starts_with('#') {
                    names.push(uri_escape::unescape(uri));
                }
            }
        }
    }
    names
}

/// Why a signature cannot be read: reported as a failed "structure" check.
#[derive(Debug)]
enum StructureError {
    Missing(&'static str),
    NoElementWithId(String),
    SeveralElementsWithId(String),
    Algorithm(AlgorithmError),
    UnsupportedTransform(String),
    TransformsOnExternalReference(String),
    UnsupportedCanonicalization(String),
    InvalidBase64,
    InvalidTime(String),
    Certificate(CertificateError),
    Key(KeyError),
    TimeStamp(TimeStampError),
    Ocsp(OcspError),
}

impl fmt::Display for StructureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(path) => write!(formatter, "{path} is missing."),
            Self::NoElementWithId(id) => write!(formatter, "No element with Id '{id}'."),
            Self::SeveralElementsWithId(id) => write!(formatter, "Several elements have Id '{id}'."),
            Self::Algorithm(error) => write!(formatter, "{error}"),
            Self::UnsupportedTransform(uri) => write!(formatter, "Transform {uri} is not supported."),
            Self::TransformsOnExternalReference(uri) => {
                write!(
                    formatter,
                    "Transforms on the external reference '{uri}' are not supported."
                )
            }
            Self::UnsupportedCanonicalization(uri) => write!(formatter, "Canonicalization {uri} is not supported."),
            Self::InvalidBase64 => write!(formatter, "The input is not a valid Base-64 string."),
            Self::InvalidTime(text) => write!(formatter, "The string '{text}' is not a valid xs:dateTime."),
            Self::Certificate(error) => write!(formatter, "{error}"),
            Self::Key(error) => write!(formatter, "{error}"),
            Self::TimeStamp(error) => write!(formatter, "{error}"),
            Self::Ocsp(error) => write!(formatter, "{error}"),
        }
    }
}

impl From<AlgorithmError> for StructureError {
    fn from(error: AlgorithmError) -> Self {
        Self::Algorithm(error)
    }
}

impl From<CertificateError> for StructureError {
    fn from(error: CertificateError) -> Self {
        Self::Certificate(error)
    }
}

/// One signature and what its verification relies on.
struct SignatureContext<'a, 'input> {
    document: &'a Document<'input>,
    signature: Node<'a, 'input>,
    resolve: &'a dyn Fn(&str) -> Option<Vec<u8>>,
    options: &'a ValidationOptions<'a>,
}

/// A reference resolved before the signer's key (and its DKE) is known.
struct ResolvedReference {
    name: String,
    hash_oid: &'static str,
    expected: Vec<u8>,
    content: Option<Vec<u8>>,
}

/// What the references of ds:SignedInfo resolve to.
struct References<'a, 'input> {
    resolved: Vec<ResolvedReference>,
    signed_properties: Option<Node<'a, 'input>>,
    has_external_files: bool,
}

fn verify_signature(context: &SignatureContext<'_, '_>, report: &mut VerificationReport) -> Result<(), StructureError> {
    let signature = context.signature;
    let signed_info = single(&signature, DS, "SignedInfo", "ds:SignedInfo")?;
    let canonicalization = single(&signed_info, DS, "CanonicalizationMethod", "ds:CanonicalizationMethod")?;
    let signature_method = single(&signed_info, DS, "SignatureMethod", "ds:SignatureMethod")?;
    let signature_method = attribute_or_empty(&signature_method, "Algorithm");
    let signature_hash = algorithms::hash_of_xml_algorithm(signature_method)?;
    let qualifying = first_on_path(&signature, &[(DS, "Object"), (XADES, "QualifyingProperties")]);
    report.signature_algorithm = Some(signature_method.to_owned());
    report.digest_algorithm = Some(signature_hash.to_owned());
    let references = resolve_references(context, &signed_info, report)?;
    let certificates = read_signature_certificates(context)?;

    if references.signed_properties.is_none() {
        let details = if qualifying.is_none() {
            "the signature has no xades:QualifyingProperties (plain XML-DSig)"
        } else {
            "no reference of this signature covers its xades:SignedProperties"
        };
        report.fail("signed properties", details);
    }
    let certificate = match references.signed_properties {
        Some(properties) => find_signing_certificate(&properties, &certificates.known, report)?,
        None => certificates.key_info.first().cloned(),
    };
    let Some(certificate) = certificate else {
        report.fail(
            "signer certificate",
            "the signer's certificate is neither in ds:KeyInfo nor given",
        );
        return Ok(());
    };
    report.signer = Some(certificate.clone());
    let key = certificate.public_key().map_err(StructureError::Key)?;
    check_references(&references.resolved, key.dke(), report);
    if let Some(properties) = references.signed_properties {
        read_claimed_signing_time(&properties, report)?;
    }
    let signed_info = SignedInfo {
        element: signed_info,
        canonicalization,
        signature_hash,
    };
    let signature_value = check_signature_value(&signature, &signed_info, &certificate, report)?;

    let signer = SignerFindings {
        certificate: &certificate,
        known: &certificates.known,
        has_certificate_values: !certificates.values.is_empty(),
        has_external_files: references.has_external_files,
    };
    verify_unsigned_properties(context, qualifying, &signature_value, &signer, report)
}

/// The certificates a signature carries: in ds:KeyInfo, in xades:CertificateValues, and with the extra ones given.
struct SignatureCertificates {
    key_info: Vec<Certificate>,
    values: Vec<Certificate>,
    known: Vec<Certificate>,
}

fn read_signature_certificates(context: &SignatureContext<'_, '_>) -> Result<SignatureCertificates, StructureError> {
    let values_path = [
        (DS, "Object"),
        (XADES, "QualifyingProperties"),
        (XADES, "UnsignedProperties"),
        (XADES, "UnsignedSignatureProperties"),
        (XADES, "CertificateValues"),
        (XADES, "EncapsulatedX509Certificate"),
    ];
    let key_info_path = [(DS, "KeyInfo"), (DS, "X509Data"), (DS, "X509Certificate")];
    let values = read_certificates(&all_on_path(&context.signature, &values_path))?;
    let key_info = read_certificates(&all_on_path(&context.signature, &key_info_path))?;
    let known = key_info
        .iter()
        .chain(&values)
        .chain(&context.options.extra_certificates)
        .cloned()
        .collect();
    Ok(SignatureCertificates {
        key_info,
        values,
        known,
    })
}

fn read_claimed_signing_time(
    signed_properties: &Node<'_, '_>,
    report: &mut VerificationReport,
) -> Result<(), StructureError> {
    let path = [(XADES, "SignedSignatureProperties"), (XADES, "SigningTime")];
    let Some(time) = first_on_path(signed_properties, &path) else {
        return Ok(());
    };
    let text = inner_text(&time);
    let text = text.trim();
    let parsed = time_text::parse_xml_date_time(text).ok_or_else(|| StructureError::InvalidTime(text.to_owned()))?;
    report.claimed_signing_time = Some(parsed);
    Ok(())
}

/// ds:SignedInfo with the method of its canonicalization and the hash of its signature.
struct SignedInfo<'a, 'input> {
    element: Node<'a, 'input>,
    canonicalization: Node<'a, 'input>,
    signature_hash: &'static str,
}

// The signature over the canonical SignedInfo; returns ds:SignatureValue, which the time-stamps cover.
fn check_signature_value<'a, 'input>(
    signature: &Node<'a, 'input>,
    signed_info: &SignedInfo<'_, '_>,
    certificate: &Certificate,
    report: &mut VerificationReport,
) -> Result<Node<'a, 'input>, StructureError> {
    let canonicalization = signed_info.canonicalization;
    let signature_value = single(signature, DS, "SignatureValue", "ds:SignatureValue")?;
    let value = decode_base64(&inner_text(&signature_value))?;
    let algorithm = canonicalization_of(attribute_or_empty(&canonicalization, "Algorithm"))?;
    let prefixes = inclusive_prefixes(&canonicalization);
    let prefixes: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let canonical = ua_xml_c14n::canonicalize(signed_info.element, algorithm, &prefixes, None);
    let key = certificate.public_key().map_err(StructureError::Key)?;
    let is_valid = key.verify_data(signed_info.signature_hash, &canonical, &value);
    let details = if is_valid {
        format!(
            "DSTU 4145 signature of {} over ds:SignedInfo",
            certificate_path_validator::short(certificate)
        )
    } else {
        "the DSTU 4145 signature does not verify".to_owned()
    };
    report.check("signature", is_valid, &details);
    Ok(signature_value)
}

/// What the signed part of a signature established, which the unsigned part builds on.
struct SignerFindings<'a> {
    certificate: &'a Certificate,
    known: &'a [Certificate],
    has_certificate_values: bool,
    has_external_files: bool,
}

fn verify_unsigned_properties(
    context: &SignatureContext<'_, '_>,
    qualifying: Option<Node<'_, '_>>,
    signature_value: &Node<'_, '_>,
    signer: &SignerFindings<'_>,
    report: &mut VerificationReport,
) -> Result<(), StructureError> {
    let path = [(XADES, "UnsignedProperties"), (XADES, "UnsignedSignatureProperties")];
    let unsigned = qualifying.and_then(|node| first_on_path(&node, &path));
    let mut pool: Vec<Certificate> = signer.known.to_vec();
    let stamps: Vec<Node<'_, '_>> = unsigned
        .iter()
        .flat_map(|node| children(node, XADES, "SignatureTimeStamp"))
        .collect();
    for stamp in &stamps {
        verify_time_stamp(context, stamp, signature_value, signer.certificate, &mut pool, report)?;
    }
    let ocsp = match unsigned {
        Some(unsigned) => read_ocsp_values(&unsigned)?,
        None => Vec::new(),
    };
    describe_format(signer, !stamps.is_empty(), !ocsp.is_empty(), report);
    let time = report.validation_time(context.options.now());
    certificate_path_validator::validate(
        signer.certificate,
        &pool,
        &ocsp,
        context.options,
        time,
        report,
        "signer",
    );
    Ok(())
}

// One xades:SignatureTimeStamp over the canonical ds:SignatureValue; its time is used when none of its checks fails.
fn verify_time_stamp(
    context: &SignatureContext<'_, '_>,
    stamp: &Node<'_, '_>,
    signature_value: &Node<'_, '_>,
    certificate: &Certificate,
    pool: &mut Vec<Certificate>,
    report: &mut VerificationReport,
) -> Result<(), StructureError> {
    let options = context.options;
    let method = match children(stamp, DS, "CanonicalizationMethod").first() {
        Some(method) => canonicalization_of(attribute_or_empty(method, "Algorithm"))?,
        None => Algorithm::Inclusive,
    };
    let covered = ua_xml_c14n::canonicalize(*signature_value, method, &[], None);
    let encapsulated = single(stamp, XADES, "EncapsulatedTimeStamp", "xades:EncapsulatedTimeStamp")?;
    let token = TimeStampToken::load(&decode_base64(&inner_text(&encapsulated))?).map_err(StructureError::TimeStamp)?;
    let before = report.checks.len();
    if let Some(downloads) = options.downloads {
        if token.find_signer_certificate(pool).is_none() {
            pool.extend(certificate_path_validator::download_issuers(certificate, downloads));
        }
    }
    let authority = token.verify(&covered, pool, report, SIGNATURE_TIME_STAMP);
    report.time_stamps.push(TimeStampDetails {
        kind: SIGNATURE_TIME_STAMP.to_owned(),
        token: token.clone(),
        authority: authority.clone(),
    });
    let Some(authority) = authority else {
        return Ok(());
    };
    pool.extend(token.cms().certificates().iter().cloned());
    let name = format!("{SIGNATURE_TIME_STAMP} service");
    certificate_path_validator::validate(&authority, pool, &[], options, token.gen_time(), report, &name);
    let has_failure = report.checks[before..]
        .iter()
        .any(|check| check.status == CheckStatus::Failed);
    if !has_failure && report.time_stamp_time.is_none() {
        report.time_stamp_time = Some(token.gen_time());
    }
    Ok(())
}

fn read_ocsp_values(unsigned: &Node<'_, '_>) -> Result<Vec<OcspResponse>, StructureError> {
    let path = [
        (XADES, "RevocationValues"),
        (XADES, "OCSPValues"),
        (XADES, "EncapsulatedOCSPValue"),
    ];
    let mut responses = Vec::new();
    for value in all_on_path(unsigned, &path) {
        responses.push(OcspResponse::load(&decode_base64(&inner_text(&value))?).map_err(StructureError::Ocsp)?);
    }
    Ok(responses)
}

fn describe_format(signer: &SignerFindings<'_>, has_time_stamp: bool, has_ocsp: bool, report: &mut VerificationReport) {
    let level = if signer.has_certificate_values || has_ocsp {
        "XAdES-B-LT"
    } else if has_time_stamp {
        "XAdES-B-T"
    } else {
        "XAdES-B-B"
    };
    let packaging = if signer.has_external_files {
        "detached"
    } else {
        "enveloped"
    };
    let hash_name = match report.digest_algorithm.as_deref() {
        Some(hash_oid) => algorithms::hash_name(hash_oid).to_owned(),
        None => String::new(),
    };
    report.format = Some(format!("{level}, {packaging}, {hash_name}"));
    report.level = Some(level.to_owned());
    report.packaging = Some(packaging.to_owned());
}

// Resolves each reference; the digests are compared once the signer's key (and its DKE) is known.
fn resolve_references<'a, 'input>(
    context: &SignatureContext<'a, 'input>,
    signed_info: &Node<'a, 'input>,
    report: &mut VerificationReport,
) -> Result<References<'a, 'input>, StructureError> {
    let mut references = References {
        resolved: Vec::new(),
        signed_properties: None,
        has_external_files: false,
    };
    for reference in children(signed_info, DS, "Reference") {
        let uri = attribute_or_empty(&reference, "URI");
        let shown = if uri.is_empty() { DOCUMENT_REFERENCE } else { uri };
        let digest_method = single(&reference, DS, "DigestMethod", "ds:DigestMethod")?;
        let hash_oid = algorithms::hash_of_xml_algorithm(attribute_or_empty(&digest_method, "Algorithm"))?;
        let expected = decode_base64(&inner_text(&single(&reference, DS, "DigestValue", "ds:DigestValue")?))?;
        let transforms = read_transforms(&reference);
        report.signed_objects.push(SignedObject {
            name: shown.to_owned(),
            hash_algorithm: hash_oid.to_owned(),
            digest: expected.clone(),
        });

        let content = if uri.is_empty() || uri.starts_with('#') {
            let target = if uri.is_empty() {
                context.document.root()
            } else {
                find_by_id(context.document, &uri[1..])?
            };
            if is_signed_properties(&target) && is_descendant(&target, &context.signature) {
                references.signed_properties = Some(target);
            }
            Some(apply_transforms(target, &transforms, context.signature)?)
        } else {
            if !transforms.is_empty() {
                return Err(StructureError::TransformsOnExternalReference(uri.to_owned()));
            }
            let content = (context.resolve)(&uri_escape::unescape(uri));
            references.has_external_files |= content.is_some();
            content
        };
        references.resolved.push(ResolvedReference {
            name: format!("reference '{shown}'"),
            hash_oid,
            expected,
            content,
        });
    }
    Ok(references)
}

fn check_references(references: &[ResolvedReference], dke: Option<&[u8]>, report: &mut VerificationReport) {
    for reference in references {
        let Some(content) = &reference.content else {
            report.fail(&reference.name, "the referenced file was not given");
            continue;
        };
        let matches = algorithms::digest_matches(reference.hash_oid, content, &reference.expected, dke);
        let details = if matches {
            format!("{} digest matches", algorithms::hash_name(reference.hash_oid))
        } else {
            "the content does not match the digest".to_owned()
        };
        report.check(&reference.name, matches, &details);
    }
}

// SigningCertificateV2 / SigningCertificate: the certificate whose digest is listed (the first Cert names the signer).
fn find_signing_certificate(
    signed_properties: &Node<'_, '_>,
    known: &[Certificate],
    report: &mut VerificationReport,
) -> Result<Option<Certificate>, StructureError> {
    let version_2 = [
        (XADES, "SignedSignatureProperties"),
        (XADES, "SigningCertificateV2"),
        (XADES, "Cert"),
    ];
    let version_1 = [
        (XADES, "SignedSignatureProperties"),
        (XADES, "SigningCertificate"),
        (XADES, "Cert"),
    ];
    let mut certs = all_on_path(signed_properties, &version_2);
    certs.extend(all_on_path(signed_properties, &version_1));
    certs.sort_by_key(|node| node.range().start);
    let Some(cert) = certs.first() else {
        report.warn(
            "signing certificate",
            "the signed properties do not name the certificate",
        );
        return Ok(known.first().cloned());
    };
    let digest = single(cert, XADES, "CertDigest", "xades:CertDigest")?;
    let hash_oid = algorithms::hash_of_xml_algorithm(attribute_or_empty(
        &single(&digest, DS, "DigestMethod", "ds:DigestMethod")?,
        "Algorithm",
    ))?;
    let expected = decode_base64(&inner_text(&single(&digest, DS, "DigestValue", "ds:DigestValue")?))?;
    let found = known
        .iter()
        .find(|candidate| {
            let dke = candidate
                .public_key()
                .ok()
                .and_then(|key| key.dke().map(<[u8]>::to_vec));
            algorithms::digest_matches(hash_oid, candidate.encoded(), &expected, dke.as_deref())
        })
        .cloned();
    let details = if found.is_some() {
        format!(
            "{} of the certificate matches the signed properties",
            algorithms::hash_name(hash_oid)
        )
    } else {
        "the signed properties name a certificate that is not available".to_owned()
    };
    report.check("signing certificate", found.is_some(), &details);
    Ok(found)
}

/// A transform: its algorithm URI and the InclusiveNamespaces prefix list.
struct Transform {
    algorithm: String,
    prefixes: Vec<String>,
}

fn read_transforms(reference: &Node<'_, '_>) -> Vec<Transform> {
    all_on_path(reference, &[(DS, "Transforms"), (DS, "Transform")])
        .iter()
        .map(|transform| Transform {
            algorithm: attribute_or_empty(transform, "Algorithm").to_owned(),
            prefixes: inclusive_prefixes(transform),
        })
        .collect()
}

// The XML-DSig processing model (XML-DSig 1.0, 4.3.3.2): a node set goes through the transforms and, if no
// canonicalization ends it, through inclusive C14N. Supported: enveloped-signature and the four C14N methods.
fn apply_transforms(
    target: Node<'_, '_>,
    transforms: &[Transform],
    signature: Node<'_, '_>,
) -> Result<Vec<u8>, StructureError> {
    let mut excluded = None;
    for transform in transforms {
        if transform.algorithm == ENVELOPED_SIGNATURE {
            excluded = Some(signature);
        } else if let Some(algorithm) = Algorithm::from_uri(&transform.algorithm) {
            let prefixes: Vec<&str> = transform.prefixes.iter().map(String::as_str).collect();
            return Ok(ua_xml_c14n::canonicalize(target, algorithm, &prefixes, excluded));
        } else {
            return Err(StructureError::UnsupportedTransform(transform.algorithm.clone()));
        }
    }
    Ok(ua_xml_c14n::canonicalize(target, Algorithm::Inclusive, &[], excluded))
}

fn canonicalization_of(uri: &str) -> Result<Algorithm, StructureError> {
    Algorithm::from_uri(uri).ok_or_else(|| StructureError::UnsupportedCanonicalization(uri.to_owned()))
}

// The PrefixList of the InclusiveNamespaces child of a method element, in any namespace.
fn inclusive_prefixes(method: &Node<'_, '_>) -> Vec<String> {
    let list = method
        .children()
        .find(|child| child.is_element() && child.tag_name().name() == INCLUSIVE_NAMESPACES);
    match list {
        Some(list) => attribute_or_empty(&list, PREFIX_LIST)
            .split(' ')
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect(),
        None => Vec::new(),
    }
}

// The single element whose Id (or ID, id) attribute is `id`.
fn find_by_id<'a, 'input>(document: &'a Document<'input>, id: &str) -> Result<Node<'a, 'input>, StructureError> {
    let matches: Vec<Node<'a, 'input>> = document
        .descendants()
        .filter(|node| node.is_element() && ["Id", "ID", "id"].iter().any(|name| node.attribute(*name) == Some(id)))
        .collect();
    match matches.as_slice() {
        [single] => Ok(*single),
        [] => Err(StructureError::NoElementWithId(id.to_owned())),
        _ => Err(StructureError::SeveralElementsWithId(id.to_owned())),
    }
}

fn is_signed_properties(node: &Node<'_, '_>) -> bool {
    node.is_element()
        && node.tag_name().name() == "SignedProperties"
        && node
            .tag_name()
            .namespace()
            .is_some_and(|namespace| namespace == XADES || namespace == XADES_141)
}

fn is_descendant(node: &Node<'_, '_>, ancestor: &Node<'_, '_>) -> bool {
    node.ancestors().skip(1).any(|candidate| candidate == *ancestor)
}

fn read_certificates(nodes: &[Node<'_, '_>]) -> Result<Vec<Certificate>, StructureError> {
    let mut certificates = Vec::new();
    for node in nodes {
        certificates.push(Certificate::load(&decode_base64(&inner_text(node))?)?);
    }
    Ok(certificates)
}

fn is_element(node: &Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element() && node.tag_name().name() == name && node.tag_name().namespace() == Some(namespace)
}

fn children<'a, 'input>(parent: &Node<'a, 'input>, namespace: &str, name: &str) -> Vec<Node<'a, 'input>> {
    parent
        .children()
        .filter(|child| is_element(child, namespace, name))
        .collect()
}

// The elements reached from `parent` by a path of child steps, in document order (XPath "a/b/c").
fn all_on_path<'a, 'input>(parent: &Node<'a, 'input>, path: &[(&str, &str)]) -> Vec<Node<'a, 'input>> {
    let mut nodes = vec![*parent];
    for (namespace, name) in path {
        nodes = nodes.iter().flat_map(|node| children(node, namespace, name)).collect();
    }
    nodes
}

fn first_on_path<'a, 'input>(parent: &Node<'a, 'input>, path: &[(&str, &str)]) -> Option<Node<'a, 'input>> {
    all_on_path(parent, path).first().copied()
}

fn single<'a, 'input>(
    parent: &Node<'a, 'input>,
    namespace: &str,
    name: &str,
    shown: &'static str,
) -> Result<Node<'a, 'input>, StructureError> {
    children(parent, namespace, name)
        .first()
        .copied()
        .ok_or(StructureError::Missing(shown))
}

// A missing attribute reads as empty, as XmlElement.GetAttribute reads it.
fn attribute_or_empty<'a>(node: &Node<'a, '_>, name: &str) -> &'a str {
    node.attribute(name).map_or("", |value| value)
}

fn inner_text(node: &Node<'_, '_>) -> String {
    node.descendants()
        .filter(Node::is_text)
        .filter_map(|text| text.text())
        .collect()
}

// Base64 with any white space in it, as Convert.FromBase64String reads it.
fn decode_base64(text: &str) -> Result<Vec<u8>, StructureError> {
    let compact: String = text.chars().filter(|character| !character.is_whitespace()).collect();
    BASE64.decode(compact).map_err(|_| StructureError::InvalidBase64)
}
