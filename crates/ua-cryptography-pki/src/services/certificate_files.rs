//! Certificates from files and downloads: DER, PEM (one or several blocks) or a CMS certificate bundle (.p7b/.p7c).

use std::path::Path;

use ua_cryptography_der::{Asn1Node, tag};

use crate::cms::SignedData;
use crate::errors::CertificateError;
use crate::x509::Certificate;

/// The line that opens a PEM certificate block.
const BEGIN_CERTIFICATE: &str = "-----BEGIN CERTIFICATE-----";
/// The line that closes a PEM certificate block.
const END_CERTIFICATE: &str = "-----END CERTIFICATE-----";

/// The certificates in `data`: every PEM block, or one DER certificate, or the certificates of a CMS bundle.
pub fn parse(data: &[u8]) -> Result<Vec<Certificate>, CertificateError> {
    let text = String::from_utf8_lossy(data);
    if text.contains(BEGIN_CERTIFICATE) {
        return text
            .split(END_CERTIFICATE)
            .filter(|block| block.contains(BEGIN_CERTIFICATE))
            .map(|block| Certificate::load(format!("{block}{END_CERTIFICATE}").as_bytes()))
            .collect();
    }
    let der = ua_cryptography_der::decode_pem(data, "CERTIFICATE")?;
    let node = Asn1Node::parse(&der)?;
    if node.child(0)?.has_tag(tag::OBJECT_IDENTIFIER) {
        let bundle = SignedData::load(&der).map_err(|error| CertificateError::Bundle(Box::new(error)))?;
        return Ok(bundle.certificates().to_vec());
    }
    Ok(vec![Certificate::load(&der)?])
}

/// The certificates in the file at `path`.
pub fn load(path: &Path) -> Result<Vec<Certificate>, CertificateError> {
    let data = std::fs::read(path).map_err(|error| CertificateError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    parse(&data)
}
