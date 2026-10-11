use crate::errors::{KeyStoreError, SigningKeyError};
use crate::keystore::{JksEntry, JksKeyStore, JksPrivateKeyEntry};
use crate::validation::certificate_path_validator;
use crate::x509::{Certificate, Dstu4145PrivateKey, KeyUsageFlags};

/// The keyUsage bits that allow signing: digitalSignature or nonRepudiation.
const SIGNING_KEY_USAGE: u32 = KeyUsageFlags::DIGITAL_SIGNATURE.0 | KeyUsageFlags::NON_REPUDIATION.0;

/// A private key with its certificate and the rest of the chain (end entity first): what a signer needs.
#[derive(Debug, Clone)]
pub struct SigningKey {
    key: Dstu4145PrivateKey,
    chain: Vec<Certificate>,
}

impl SigningKey {
    /// The key with its chain; the first certificate must certify the key.
    pub fn new(key: Dstu4145PrivateKey, chain: Vec<Certificate>) -> Result<Self, SigningKeyError> {
        let certificate = chain.first().ok_or(SigningKeyError::MissingCertificate)?;
        let certified = certificate.public_key().map_err(SigningKeyError::Key)?;
        if certified.q() != key.public_key().q() {
            return Err(SigningKeyError::KeyMismatch);
        }
        Ok(Self { key, chain })
    }

    /// The private key.
    pub fn key(&self) -> &Dstu4145PrivateKey {
        &self.key
    }

    /// The signer's certificate (the first of the chain).
    pub fn certificate(&self) -> &Certificate {
        &self.chain[0]
    }

    /// The chain, the signer's certificate first.
    pub fn chain(&self) -> &[Certificate] {
        &self.chain
    }

    /// Opens a key from a JKS store. Without `alias` the store must hold exactly one private key, or exactly one with
    /// an end-entity certificate that allows signing (keyUsage digitalSignature or nonRepudiation). The chain is
    /// rebuilt from the key's certificate up through its issuers, whatever order the store keeps it in; certificates
    /// off that path (such as a key-agreement certificate) are left out. `key_password` defaults to `password`.
    pub fn from_jks(
        store: &JksKeyStore,
        password: &str,
        alias: Option<&str>,
        key_password: Option<&str>,
    ) -> Result<Self, KeyStoreError> {
        let entry = match alias {
            Some(alias) => match store.find(alias) {
                Some(JksEntry::PrivateKey(entry)) => entry,
                _ => {
                    return Err(KeyStoreError::NoPrivateKey {
                        alias: alias.to_owned(),
                    });
                }
            },
            None => select_signing_entry(store)?,
        };
        let key_password = match key_password {
            Some(key_password) => key_password,
            None => password,
        };
        let key = entry.get_private_key(key_password)?;
        let chain = match entry.find_certificate(key.public_key()) {
            Some(certificate) => certificate_path_validator::build_chain(certificate, &entry.chain, &[], None),
            None => entry.chain.clone(),
        };
        Ok(Self::new(key, chain)?)
    }
}

fn select_signing_entry(store: &JksKeyStore) -> Result<&JksPrivateKeyEntry, KeyStoreError> {
    let mut keys: Vec<&JksPrivateKeyEntry> = store.private_keys().collect();
    if keys.len() > 1 {
        keys.retain(|entry| entry.chain.iter().any(allows_signing));
    }
    match keys.as_slice() {
        [single] => Ok(single),
        [] => Err(KeyStoreError::NoSigningKey),
        _ => Err(KeyStoreError::SeveralKeys {
            aliases: store.private_keys().map(|entry| entry.alias.clone()).collect(),
        }),
    }
}

fn allows_signing(certificate: &Certificate) -> bool {
    !certificate.is_ca()
        && certificate
            .key_usage()
            .is_none_or(|usage| usage & SIGNING_KEY_USAGE != 0)
}
