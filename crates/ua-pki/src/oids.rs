//! Object identifiers of the Ukrainian PKI and of the formats of this crate (docs/signature-formats.md, section 2).

// ---- Ukrainian algorithms (arc 1.2.804.2.1.1.1) ----

/// GOST 34.311-95 hash.
pub const GOST34311: &str = "1.2.804.2.1.1.1.1.2.1";
/// DSTU 7564:2014 hash, 256 bits.
pub const DSTU7564_256: &str = "1.2.804.2.1.1.1.1.2.2.1";
/// DSTU 7564:2014 hash, 384 bits.
pub const DSTU7564_384: &str = "1.2.804.2.1.1.1.1.2.2.2";
/// DSTU 7564:2014 hash, 512 bits.
pub const DSTU7564_512: &str = "1.2.804.2.1.1.1.1.2.2.3";
/// DSTU 4145 key with little-endian octet strings; the same OID names "DSTU 4145 with GOST 34.311".
pub const DSTU4145_LE: &str = "1.2.804.2.1.1.1.1.3.1.1";
/// DSTU 4145 key with big-endian octet strings.
pub const DSTU4145_BE: &str = "1.2.804.2.1.1.1.1.3.1.1.1.1";
/// Signature algorithm DSTU 4145 with GOST 34.311.
pub const DSTU4145_WITH_GOST34311: &str = DSTU4145_LE;
/// Signature algorithm DSTU 4145 with DSTU 7564-256.
pub const DSTU4145_WITH_DSTU7564: &str = "1.2.804.2.1.1.1.1.3.6.1.1";
/// Named curves: the i-th curve of table Г.1 of DSTU 4145-2002 is this prefix followed by i.
pub const NAMED_CURVE_PREFIX: &str = "1.2.804.2.1.1.1.1.3.1.1.2.";
/// Time-stamping policy used with GOST 34.311.
pub const TSP_POLICY_GOST34311: &str = "1.2.804.2.1.1.1.2.3.1";
/// Time-stamping policy used with DSTU 7564.
pub const TSP_POLICY_DSTU7564: &str = "1.2.804.2.1.1.1.2.3.4.1.1";

// ---- International hashes (ESS certificate identifiers default to them) ----

/// SHA-1.
pub const SHA1: &str = "1.3.14.3.2.26";
/// SHA-256.
pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";

// ---- X.500 attribute types ----

/// commonName (CN).
pub const COMMON_NAME: &str = "2.5.4.3";
/// surname (SN).
pub const SURNAME: &str = "2.5.4.4";
/// serialNumber (SERIALNUMBER).
pub const SERIAL_NUMBER: &str = "2.5.4.5";
/// countryName (C).
pub const COUNTRY: &str = "2.5.4.6";
/// localityName (L).
pub const LOCALITY: &str = "2.5.4.7";
/// stateOrProvinceName (ST).
pub const STATE: &str = "2.5.4.8";
/// streetAddress (STREET).
pub const STREET: &str = "2.5.4.9";
/// organizationName (O).
pub const ORGANIZATION: &str = "2.5.4.10";
/// organizationalUnitName (OU).
pub const ORGANIZATIONAL_UNIT: &str = "2.5.4.11";
/// title (T).
pub const TITLE: &str = "2.5.4.12";
/// givenName (G).
pub const GIVEN_NAME: &str = "2.5.4.42";
/// organizationIdentifier.
pub const ORGANIZATION_IDENTIFIER: &str = "2.5.4.97";
/// emailAddress (E).
pub const EMAIL_ADDRESS: &str = "1.2.840.113549.1.9.1";

// ---- X.509 extensions (RFC 5280) ----

/// subjectKeyIdentifier.
pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
/// keyUsage.
pub const KEY_USAGE: &str = "2.5.29.15";
/// basicConstraints.
pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
/// authorityKeyIdentifier.
pub const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
/// extKeyUsage.
pub const EXTENDED_KEY_USAGE: &str = "2.5.29.37";
/// authorityInfoAccess.
pub const AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
/// subjectInfoAccess.
pub const SUBJECT_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.11";
/// id-ad-ocsp.
pub const ACCESS_OCSP: &str = "1.3.6.1.5.5.7.48.1";
/// id-ad-caIssuers.
pub const ACCESS_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
/// id-ad-timeStamping.
pub const ACCESS_TIME_STAMPING: &str = "1.3.6.1.5.5.7.48.3";
/// id-kp-timeStamping.
pub const KEY_PURPOSE_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
/// id-kp-OCSPSigning.
pub const KEY_PURPOSE_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

// ---- CMS (RFC 5652) and its attributes ----

/// id-data.
pub const DATA: &str = "1.2.840.113549.1.7.1";
/// id-signedData.
pub const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// id-ct-TSTInfo.
pub const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
/// contentType.
pub const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
/// messageDigest.
pub const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
/// signingTime.
pub const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
/// signingCertificate (ESS, SHA-1).
pub const SIGNING_CERTIFICATE: &str = "1.2.840.113549.1.9.16.2.12";
/// signingCertificateV2 (RFC 5035).
pub const SIGNING_CERTIFICATE_V2: &str = "1.2.840.113549.1.9.16.2.47";
/// signatureTimeStampToken.
pub const SIGNATURE_TIME_STAMP_TOKEN: &str = "1.2.840.113549.1.9.16.2.14";
/// contentTimeStamp.
pub const CONTENT_TIME_STAMP: &str = "1.2.840.113549.1.9.16.2.20";
/// completeCertificateRefs.
pub const CERTIFICATE_REFS: &str = "1.2.840.113549.1.9.16.2.21";
/// completeRevocationRefs.
pub const REVOCATION_REFS: &str = "1.2.840.113549.1.9.16.2.22";
/// certValues.
pub const CERT_VALUES: &str = "1.2.840.113549.1.9.16.2.23";
/// revocationValues.
pub const REVOCATION_VALUES: &str = "1.2.840.113549.1.9.16.2.24";

// ---- OCSP (RFC 6960) ----

/// id-pkix-ocsp-basic.
pub const OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";
/// id-pkix-ocsp-nonce.
pub const OCSP_NONCE: &str = "1.3.6.1.5.5.7.48.1.2";

// ---- Key stores ----

/// The Sun JKS key protector.
pub const JKS_KEY_PROTECTOR: &str = "1.3.6.1.4.1.42.2.17.1.1";
