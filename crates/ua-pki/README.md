# ua-pki

The formats of the Ukrainian PKI over DSTU 4145 — X.509, JKS, CMS/CAdES, RFC 3161 time-stamps, OCSP, XAdES, ASiC,
certification paths and the HTTP clients of the PKI services — written so that what it makes is what Ukrainian
qualified tools make, and what they make verifies.

## API

```rust
use ua_pki::{
    CadesOptions, CadesSigner, HttpOcspService, HttpTimeStampService, JksKeyStore, SignatureLevel, SignatureServices,
    SigningKey, ValidationOptions, signature_verifier,
};

// Sign: a key from a JKS store, a CAdES-T with the time-stamping service named in the certificate.
let store = JksKeyStore::load(&std::fs::read("key.jks")?, "password")?;
let signer = SigningKey::from_jks(&store, "password", None, None)?;
let tsa = HttpTimeStampService::new(&signer.certificate().time_stamp_urls()[0]);
let services = SignatureServices { time_stamps: Some(&tsa), ..SignatureServices::default() };
let options = CadesOptions { level: SignatureLevel::T, ..CadesOptions::default() };
let signature = CadesSigner::new(signer, services).sign(b"document", &options)?;

// Verify any format (CAdES, XAdES, ASiC-S, ASiC-E): a report per signature, with every check.
let ocsp = HttpOcspService::new(None);
let options = ValidationOptions { trust_anchors: roots, online_ocsp: Some(&ocsp), ..ValidationOptions::default() };
let result = signature_verifier::verify(&signature, &|_name| None, &options)?;
for report in &result.signatures {
    for check in &report.checks {
        println!("{:?} {}: {}", check.status, check.name, check.details);
    }
}
assert!(result.is_valid());
```

| Area | Items |
|---|---|
| identifiers | `oids::*` (OID constants), `xml_namespaces::*`; `algorithms::{hash, candidate_hashes, digest_matches, is_supported_hash, hash_of_signature_algorithm, signature_algorithm_for, xml_digest_method, xml_signature_method, hash_of_xml_algorithm, parse_hash_name, hash_name, signature_algorithm_name}` and the XML algorithm URIs |
| X.509 | `Certificate::load` (DER/PEM/base64) and its fields, `public_key()` (checked by 8 and 10.1, decoded once), `is_ca`, `key_usage`, `extended_key_usage`, `subject_key_identifier`, `authority_key_identifier`, `ocsp_urls`, `ca_issuer_urls`, `time_stamp_urls`, `is_signed_by`, `is_valid_at`; `DistinguishedName::{parse, from_asn1, find_attribute}`; `CertificateBuilder` (`new`, `add_*`, `self_sign`, `issue`, `key_identifier`); `KeyUsageFlags` |
| keys | `Dstu4145PublicKey` (`from_subject_public_key_info`, `to_subject_public_key_info`, `verify_hash`, `verify_data`, `verify`); `Dstu4145PrivateKey` (`new`, `generate`, `sign_hash`, `sign`, `to_pkcs8`, `from_pkcs8`); `JksKeyStore` (`load`, `save`, `find`, `private_keys`, `add_private_key`, `add_trusted_certificate`), `JksEntry`, `JksPrivateKeyEntry::{find_certificate, decrypt_pkcs8, get_private_key}`, `JksTrustedCertificateEntry`; `SigningKey::{new, from_jks}` |
| CMS, TSP, OCSP | `SignedData::load`, `SignerInfo`, `CmsAttribute`; `cms_builder::{attribute, signing_certificate_v2, issuer_serial, signed_attributes, signer_info, signer_info_with, signed_data}`; `cms_verifier::{verify_signer, check_signing_certificate}`; `TimeStampToken` (`load`, `covers`, `find_signer_certificate`, `verify`); `time_stamp_protocol::{create_nonce, create_request, parse_response}`; `OcspResponse` (`load`, `load_basic`, `full_encoded`, `find`, `find_responder`, `is_signed_by`, `create_request`), `OcspSingleResponse::matches`, `OcspCertificateStatus` |
| services | traits `TimeStampService::get_token`, `OcspService::find_response`, `CertificateSource::download_certificates`; `HttpTimeStampService`, `HttpOcspService`, `HttpCertificateSource` (ureq, 30 s timeout, answers up to 10 MiB); `LongTermValidationData::collect`; `certificate_files::{parse, load}` |
| signing | `CadesSigner` + `CadesOptions` (B, T, LT = CAdES-X Long; content time-stamp; detached); `XadesSigner::{sign, sign_to_bytes}` → `XadesSignature` (B, T, LT); `asic_container::{create_asic_s, create_asic_e, looks_like_zip}`; `SignatureServices`, `SignatureLevel`; `mime_type_of` |
| verification | `signature_verifier::verify` (by content), `cades_verifier::verify`, `xades_verifier::{verify, external_references}`, `certificate_path_validator::{build_chain, download_issuers, validate, short}`; `ValidationOptions` (trust anchors, extra certificates, online OCSP, downloads, injectable "now"); `VerificationResult`, `VerificationReport` (`pass`/`warn`/`fail`/`check`, `is_valid`, `has_warnings`, `validation_time`), `VerificationCheck`, `CheckStatus`, `SignedObject`, `TimeStampDetails`, `CertificatePath`, `RevocationStatus` |

Errors, one type per reason to refuse, causes kept in `source()`: `AlgorithmError`, `CertificateError`,
`DistinguishedNameError`, `KeyError`, `KeyStoreError`, `SigningKeyError`, `CmsError`, `TimeStampError`, `OcspError`,
`ServiceError`, `SigningError`, `ContainerError`, `VerificationError` (an unreadable input; a signature that is read
but does not hold is a report with failed checks, not an error).

Models carry data in `pub` fields (`VerificationReport`, `OcspSingleResponse`, `JksPrivateKeyEntry`, …); the types
parsed from bytes (`Certificate`, `SignedData`, `SignerInfo`, `TimeStampToken`, `OcspResponse`) keep their fields
behind accessors, so the fields always agree with the bytes.

## Conventions

The byte orders, attributes, identifiers and XML shapes are those of docs/signature-formats.md and
docs/provider-formats.md: the hash is reversed before DSTU 4145 and D is stored little-endian; GOST 34.311 hashes with
the signer's DKE and, when that is not DKE No. 1, DKE No. 1 is accepted too; XAdES is written exactly as the C#
`XadesSigner` writes it (prefixes `ds`/`xades`, Ids `S-…`, element and attribute order, `<x />` empty elements), and
ASiC-E manifests byte for byte.

XAdES is built as text (no mutable DOM) and canonicalized with `ua-xml-c14n` over `roxmltree`; verification works on
a `roxmltree::Document`. Against signature wrapping, same-document references must resolve to exactly one element, and
the signed properties are read only from the element the signature covers.

## Boundaries

- No PAdES, CRLs, archive time-stamps (B-LTA), PKCS#12 or IIT key containers; certificate policies are not evaluated;
  CAdES signatures inside ASiC-E (ASiCManifest) are reported, not verified.
- Path validation is a subset of RFC 5280, section 6: signatures, validity, basicConstraints cA, trust anchor, OCSP of
  every certificate below the top (embedded, else online when allowed).
- DSTU 4145 keys only; other certificates parse, list and match, but their keys are refused when used.
- `generate`, nonces, salts and serial numbers take randomness from the OS (`rand_core::OsRng`); signing times are
  "now" (the verifier's "now" is injectable through `ValidationOptions::current_time`).

## Dependencies

The workspace crates `ua-gf2m`, `ua-gost`, `ua-dstu4145`, `ua-dstu7564`, `ua-der`, `ua-xml-c14n`; `num-bigint`,
`num-traits`, `rand_core`, `sha1`, `sha2`, `base64`, `time`, `roxmltree`, `zip` (deflate only), `ureq` 2. Tests:
`serde_json` reads the fixtures recorded by `tools/csharp-oracle` in `testdata/oracle/pki`.

## Visibility

Public: meant for crates.io, `publish = false` until the author decides.

## Why not a ready crate

Rust has X.509/CMS crates (`x509-cert`, `cms`, `rasn`), but none knows DSTU 4145 keys (named curves of table Г.1 and
explicit ECBinary parameters in both byte orders, the DKE), the national signature value encodings or the shapes
Ukrainian tools write; there is no JKS reader with the Sun key protector, no XAdES signer and no ASiC crate that would
produce containers these tools accept. Matching the C# reference byte for byte (checked by the oracle fixtures) is
simpler over `ua-der` than through a generic ASN.1 framework.

## Tests

`tests/` ports the C# tests of `Pki/**` and `Signatures/**` over the recorded fixtures (`testdata/oracle/pki`):
the 66 signatures of `manifest.json` get the C# verdicts and exactly the C# checks; C#-made key stores, tokens,
OCSP responses and requests are read and compared; Rust-made XAdES and ASiC-E have the structure (and the manifest the
bytes) the C# package writes; every signature the crate makes is checked by independent recipes (`tests/common/recipes.rs`,
`ua-der` + `ua-dstu4145` only) and by the crate's verifier. In-process fakes stand in for the time-stamping service and
the OCSP responders (`tests/common/mod.rs`), and a small HTTP server on `std::net::TcpListener` for the HTTP clients
(`tests/common/local_server.rs`).

## Ported from

`UA.Cryptography.Pki` (all but `Asn1/` and `Xml/`, which are `ua-der` and `ua-xml-c14n`) of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp).
