/// The integers r and s of a DSTU 4145 signature (5.11), big-endian.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHalves {
    /// r.
    pub r: Vec<u8>,
    /// s.
    pub s: Vec<u8>,
}
