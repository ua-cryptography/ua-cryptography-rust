use ua_cryptography_pki::{Certificate, SigningKey};

/// What a signing request signs with and which services its options need; the binding connects those services.
#[derive(Debug, Clone)]
pub struct SigningPlan {
    /// The key of the request's store, with its chain.
    pub signer: SigningKey,
    /// The request's CA certificates completing the signer's chain.
    pub extra_certificates: Vec<Certificate>,
    /// The time-stamping service; present when level T, LT or a content time-stamp needs one.
    pub tsa_url: Option<String>,
    /// Level LT: the OCSP responders and caIssuers downloads are asked too.
    pub is_long_term: bool,
}
