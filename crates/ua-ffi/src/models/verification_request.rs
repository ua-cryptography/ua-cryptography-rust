use ua_pki::SignedFile;

/// A signature to verify and what it is verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationRequest {
    /// The signature: CAdES (DER, PEM or base64), XAdES, ASiC-S or ASiC-E; the format is recognised by the content.
    pub signature: Vec<u8>,
    /// The data of a detached signature, each under the name a XAdES reference uses; one file stands for any name.
    pub data: Vec<SignedFile>,
    /// Trusted roots (DER, PEM or a bundle each).
    pub trust_anchors: Vec<Vec<u8>>,
    /// Further certificates for the paths (DER, PEM or a bundle each).
    pub certificates: Vec<Vec<u8>>,
    /// Whether OCSP responders and caIssuers are asked over the network.
    pub is_online: bool,
}
