use time::OffsetDateTime;

use crate::errors::KeyStoreError;
use crate::keystore::key_protector;
use crate::x509::{Certificate, Dstu4145PrivateKey, Dstu4145PublicKey};

/// A PrivateKeyEntry: the key protected by the Sun key protector and its certificate chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JksPrivateKeyEntry {
    /// The alias.
    pub alias: String,
    /// When the entry was created.
    pub created: OffsetDateTime,
    /// The DER EncryptedPrivateKeyInfo as stored.
    pub protected_key: Vec<u8>,
    /// The certificate chain as stored (keytool writes the end entity first).
    pub chain: Vec<Certificate>,
}

impl JksPrivateKeyEntry {
    /// The certificate of `key` in the chain. keytool stores it first; some banks store the chain root first and add
    /// the certificate of the key-agreement key after the signing one.
    pub fn find_certificate(&self, key: &Dstu4145PublicKey) -> Option<&Certificate> {
        self.chain.iter().find(|certificate| {
            certificate.has_dstu4145_key()
                && certificate.public_key().is_ok_and(|certified| {
                    certified.domain().field().m() == key.domain().field().m() && certified.q() == key.q()
                })
        })
    }

    /// The PKCS#8 PrivateKeyInfo. The caller should wipe it after use.
    pub fn decrypt_pkcs8(&self, password: &str) -> Result<Vec<u8>, KeyStoreError> {
        key_protector::unprotect_key(&self.protected_key, password)
    }

    /// The DSTU 4145 private key; when the chain holds DSTU 4145 certificates, one of them must be the key's.
    pub fn get_private_key(&self, password: &str) -> Result<Dstu4145PrivateKey, KeyStoreError> {
        let mut pkcs8 = self.decrypt_pkcs8(password)?;
        let key = Dstu4145PrivateKey::from_pkcs8(&pkcs8);
        pkcs8.fill(0);
        let key = key?;
        let has_dstu4145_chain = self.chain.iter().any(Certificate::has_dstu4145_key);
        if has_dstu4145_chain && self.find_certificate(key.public_key()).is_none() {
            return Err(KeyStoreError::KeyCertificateMismatch {
                alias: self.alias.clone(),
            });
        }
        Ok(key)
    }
}
