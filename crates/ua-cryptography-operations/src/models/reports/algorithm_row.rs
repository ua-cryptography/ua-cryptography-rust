use serde::Serialize;

/// An algorithm as a signature or a certificate names it, with its readable name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlgorithmRow {
    /// An OID in CMS and X.509, a URI in XML-DSig.
    pub identifier: String,
    /// E.g. "DSTU 7564-256"; the identifier itself when it has no name.
    pub name: String,
}
