/// A file covered by a detached XAdES signature (or held by a container): the name its reference uses and its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFile {
    /// The name, as the reference URI names it before URI escaping.
    pub name: String,
    /// The content.
    pub content: Vec<u8>,
}
