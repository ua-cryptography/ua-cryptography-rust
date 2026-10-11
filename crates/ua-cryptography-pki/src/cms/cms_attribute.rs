/// A CMS attribute: its type and the DER encodings of the values of its SET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmsAttribute {
    /// The attribute type OID.
    pub oid: String,
    /// The DER encoding of each value.
    pub values: Vec<Vec<u8>>,
}

impl CmsAttribute {
    /// The DER encoding of the first value; none when the SET is empty.
    pub fn value(&self) -> Option<&[u8]> {
        self.values.first().map(Vec::as_slice)
    }
}
