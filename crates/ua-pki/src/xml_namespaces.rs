//! The XML namespaces and URIs of XML-DSig and XAdES that this crate writes and reads.

/// XML-DSig.
pub const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// XAdES 1.3.2.
pub const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
/// XAdES 1.4.1 (also accepted for SignedProperties).
pub const XADES_141: &str = "http://uri.etsi.org/01903/v1.4.1#";
/// The Type of the reference to the signed properties.
pub const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
/// The enveloped-signature transform.
pub const ENVELOPED_SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
