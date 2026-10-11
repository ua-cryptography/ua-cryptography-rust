//! JKS key stores with DSTU 4145 keys: creating one as `ua-sign keygen` does, and reading what one holds.

use time::{Duration, OffsetDateTime};
use ua_cryptography_pki::{
    CertificateBuilder, DistinguishedName, Dstu4145PrivateKey, JksEntry, JksKeyStore, KeyUsageFlags, SigningKey,
    algorithms,
};

use crate::errors::OperationFailure;
use crate::models::reports::{KeyStoreEntryKind, KeyStoreEntryRow};
use crate::models::{CreatedKeyStore, KeyStoreRequest};
use crate::operations::certificate_details::describe_certificate;
use crate::utils::format_time;

/// A store with a new key on the curve of table Г.1 and its self-signed certificate (not a CA, digitalSignature
/// and nonRepudiation, a subject key identifier), valid from `now`.
pub fn create_key_store(request: &KeyStoreRequest, now: OffsetDateTime) -> Result<CreatedKeyStore, OperationFailure> {
    if request.password.is_empty() {
        return Err(OperationFailure::invalid_argument("The key store password is empty."));
    }
    if request.validity_days == 0 {
        return Err(OperationFailure::invalid_argument(
            "The certificate must be valid for a day at least.",
        ));
    }
    if !ua_cryptography_dstu4145::POLYNOMIAL_DEGREES.contains(&request.m) {
        return Err(OperationFailure::invalid_argument(format!(
            "Table Г.1 has no curve with m = {}: {:?}.",
            request.m,
            ua_cryptography_dstu4145::POLYNOMIAL_DEGREES
        )));
    }
    let subject = DistinguishedName::parse(&request.subject)?;
    let domain = ua_cryptography_dstu4145::get_polynomial_curve(request.m)?;
    let key = Dstu4145PrivateKey::generate(&domain);

    let usage = KeyUsageFlags(KeyUsageFlags::DIGITAL_SIGNATURE.0 | KeyUsageFlags::NON_REPUDIATION.0);
    let mut builder = CertificateBuilder::new(subject, key.public_key().clone())?
        .add_basic_constraints(false)
        .add_key_usage(usage)
        .add_subject_key_identifier();
    builder.not_before = now;
    builder.not_after = now + Duration::days(i64::from(request.validity_days));
    builder.signature_algorithm = algorithms::signature_algorithm_for(request.signature_hash.oid())?.to_owned();
    let certificate = builder.self_sign(&key)?;

    let mut store = JksKeyStore::new();
    store.add_private_key(&request.alias, &key, vec![certificate.clone()], &request.password)?;
    Ok(CreatedKeyStore {
        key_store: store.save(&request.password)?,
        certificate: certificate.encoded().to_vec(),
    })
}

/// The certificate (DER) of the signing key `alias`, or of the one signing key of the store.
pub fn get_certificate(key_store: &[u8], password: &str, alias: Option<&str>) -> Result<Vec<u8>, OperationFailure> {
    let store = JksKeyStore::load(key_store, password)?;
    let signer = SigningKey::from_jks(&store, password, alias, None)?;
    Ok(signer.certificate().encoded().to_vec())
}

/// Every entry of the store with its certificates.
pub fn get_key_store_entries(key_store: &[u8], password: &str) -> Result<Vec<KeyStoreEntryRow>, OperationFailure> {
    let store = JksKeyStore::load(key_store, password)?;
    let rows = store
        .entries()
        .iter()
        .map(|entry| match entry {
            JksEntry::PrivateKey(key) => KeyStoreEntryRow {
                alias: key.alias.clone(),
                kind: KeyStoreEntryKind::PrivateKey,
                created: format_time(key.created),
                certificates: key.chain.iter().map(describe_certificate).collect(),
            },
            JksEntry::TrustedCertificate(trusted) => KeyStoreEntryRow {
                alias: trusted.alias.clone(),
                kind: KeyStoreEntryKind::TrustedCertificate,
                created: format_time(trusted.created),
                certificates: vec![describe_certificate(&trusted.certificate)],
            },
        })
        .collect();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::FailureKind;
    use crate::models::simple_types::SignatureHash;

    fn request() -> KeyStoreRequest {
        KeyStoreRequest {
            subject: "CN=Test,O=Organization,C=UA".to_owned(),
            alias: "key".to_owned(),
            m: 163,
            validity_days: 30,
            signature_hash: SignatureHash::Dstu7564,
            password: "password".to_owned(),
        }
    }

    #[test]
    fn a_created_store_opens_and_lists_its_key() {
        let now = time::macros::datetime!(2026-01-01 00:00:00 UTC);
        let created = create_key_store(&request(), now).unwrap();
        assert_eq!(
            get_certificate(&created.key_store, "password", None).unwrap(),
            created.certificate
        );
        let entries = get_key_store_entries(&created.key_store, "password").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "key");
        assert_eq!(entries[0].certificates[0].valid_to, "2026-01-31T00:00:00Z");
    }

    #[test]
    fn a_wrong_password_is_told_apart() {
        let created = create_key_store(&request(), OffsetDateTime::now_utc()).unwrap();
        let failure = get_certificate(&created.key_store, "wrong", None).unwrap_err();
        assert_eq!(failure.kind, FailureKind::WrongPassword);
    }

    #[test]
    fn a_curve_outside_table_g1_is_refused() {
        let request = KeyStoreRequest { m: 200, ..request() };
        assert!(create_key_store(&request, OffsetDateTime::now_utc()).is_err());
    }
}
