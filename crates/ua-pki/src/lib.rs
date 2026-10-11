//! The formats of the Ukrainian PKI over DSTU 4145: X.509, JKS, CMS/CAdES, RFC 3161 time-stamps, OCSP, XAdES,
//! ASiC, certification paths and the HTTP clients of the PKI services.
//!
//! - [`oids`], [`algorithms`]: the identifiers of the national PKI; hashes by OID and XML URI.
//! - X.509: [`Certificate`], [`DistinguishedName`], [`Dstu4145PublicKey`], [`Dstu4145PrivateKey`] (SPKI, PKCS#8),
//!   [`CertificateBuilder`].
//! - Keys: [`JksKeyStore`] (Sun JKS), [`SigningKey`] (a key with its chain).
//! - CMS: [`SignedData`], [`SignerInfo`]; [`cms_builder`] writes one-signer SignedData, [`cms_verifier`] checks a
//!   signer.
//! - Time-stamps and OCSP: [`TimeStampToken`], [`time_stamp_protocol`]; [`OcspResponse`].
//! - Services: the traits [`TimeStampService`], [`OcspService`], [`CertificateSource`] with their HTTP clients
//!   ([`HttpTimeStampService`], [`HttpOcspService`], [`HttpCertificateSource`]); [`LongTermValidationData`];
//!   [`certificate_files`] reads certificate files and bundles.
//! - Signing: [`CadesSigner`], [`XadesSigner`], [`asic_container`]; the services a signer uses are
//!   [`SignatureServices`].
//! - Verification: [`signature_verifier`] (any format), [`cades_verifier`], [`xades_verifier`],
//!   [`certificate_path_validator`]; outcomes are [`VerificationResult`] / [`VerificationReport`] models, not errors.

#![forbid(unsafe_code)]

pub mod algorithms;
pub mod asic_container;
mod cades;
mod cms;
mod errors;
mod keystore;
mod ocsp;
pub mod oids;
mod services;
mod signature_level;
mod signature_services;
pub mod signature_verifier;
mod signing_key;
mod time_text;
mod tsp;
mod validation;
mod x509;
mod xades;
pub mod xml_namespaces;

pub use cades::CadesSigner;
pub use cms::SignedData;
pub use cms::SignerInfo;
pub use keystore::JksKeyStore;
pub use ocsp::OcspResponse;
pub use services::CertificateSource;
pub use services::HttpCertificateSource;
pub use services::HttpOcspService;
pub use services::HttpTimeStampService;
pub use services::LongTermValidationData;
pub use services::OcspService;
pub use services::TimeStampService;
pub use signing_key::SigningKey;
pub use tsp::TimeStampToken;
pub use x509::Certificate;
pub use x509::CertificateBuilder;
pub use x509::Dstu4145PrivateKey;
pub use x509::Dstu4145PublicKey;
pub use xades::XadesSignature;
pub use xades::XadesSigner;

pub use errors::AlgorithmError;
pub use errors::CertificateError;
pub use errors::CmsError;
pub use errors::ContainerError;
pub use errors::DistinguishedNameError;
pub use errors::KeyError;
pub use errors::KeyStoreError;
pub use errors::OcspError;
pub use errors::ServiceError;
pub use errors::SigningError;
pub use errors::SigningKeyError;
pub use errors::TimeStampError;
pub use errors::VerificationError;

pub use cades::CadesOptions;
pub use cms::CmsAttribute;
pub use keystore::JksEntry;
pub use keystore::JksPrivateKeyEntry;
pub use keystore::JksTrustedCertificateEntry;
pub use ocsp::OcspSingleResponse;
pub use signature_services::SignatureServices;
pub use validation::CertificatePath;
pub use validation::RevocationStatus;
pub use validation::SignedObject;
pub use validation::TimeStampDetails;
pub use validation::ValidationOptions;
pub use validation::VerificationCheck;
pub use validation::VerificationReport;
pub use validation::VerificationResult;
pub use x509::CertificateExtension;
pub use x509::DistinguishedName;
pub use xades::SignedFile;

pub use ocsp::OcspCertificateStatus;
pub use signature_level::SignatureLevel;
pub use validation::CheckStatus;
pub use x509::KeyUsageFlags;

pub use cades::cades_verifier;
pub use cms::cms_builder;
pub use cms::cms_verifier;
pub use services::certificate_files;
pub use tsp::time_stamp_protocol;
pub use validation::certificate_path_validator;
pub use xades::mime_type_of;
pub use xades::xades_verifier;
