/// An X.509 v3 extension: its OID, criticality and the DER value inside the OCTET STRING.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateExtension {
    /// The extension OID.
    pub oid: String,
    /// The critical flag.
    pub is_critical: bool,
    /// The DER value (the contents of extnValue).
    pub value: Vec<u8>,
}
