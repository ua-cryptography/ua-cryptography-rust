use crate::validation::VerificationReport;
use crate::xades::SignedFile;

/// The outcome of verifying a signed file: one report per signature and the signed content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationResult {
    /// The container found, e.g. "CAdES (enveloped)" or "ASiC-E".
    pub format: String,
    /// One report per signature (for ASiC, the container's structure first).
    pub signatures: Vec<VerificationReport>,
    /// The signed files by name (the encapsulated content of a CAdES signature is named "content").
    pub signed_files: Vec<SignedFile>,
}

impl VerificationResult {
    /// True when there is at least one signature and none has a failed check.
    pub fn is_valid(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(VerificationReport::is_valid)
    }

    /// The content of the signed file `name`, if the result has it.
    pub fn find_signed_file(&self, name: &str) -> Option<&[u8]> {
        self.signed_files
            .iter()
            .find(|file| file.name == name)
            .map(|file| file.content.as_slice())
    }
}
