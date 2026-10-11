/// What a signature covers: a reference (XAdES) or the content (CAdES), with the digest the signature holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedObject {
    /// The reference URI or "content".
    pub name: String,
    /// The hash OID.
    pub hash_algorithm: String,
    /// The digest the signature holds.
    pub digest: Vec<u8>,
}
