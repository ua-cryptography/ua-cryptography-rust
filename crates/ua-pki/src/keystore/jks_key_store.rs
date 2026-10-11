use time::OffsetDateTime;

use crate::errors::KeyStoreError;
use crate::keystore::java_data::{self, JavaReader};
use crate::keystore::key_protector::{self, SHA1_BYTES};
use crate::keystore::{JksEntry, JksPrivateKeyEntry, JksTrustedCertificateEntry};
use crate::x509::{Certificate, Dstu4145PrivateKey};

/// The magic number of JKS.
const MAGIC: u32 = 0xFEED_FEED;
/// The version written.
const VERSION_2: u32 = 2;
/// The version without certificate types.
const VERSION_1: u32 = 1;
/// The entry tag of a PrivateKeyEntry.
const PRIVATE_KEY_TAG: u32 = 1;
/// The entry tag of a TrustedCertEntry.
const TRUSTED_CERTIFICATE_TAG: u32 = 2;
/// The shortest key store: the header and the integrity hash.
const MIN_STORE_BYTES: usize = 32;
/// The salt of the integrity hash.
const INTEGRITY_SALT: &[u8] = b"Mighty Aphrodite";
/// The certificate type of version 2.
const X509_TYPE: &str = "X.509";
/// Nanoseconds in a millisecond (Java stores milliseconds since the epoch).
const NANOSECONDS_PER_MILLISECOND: i128 = 1_000_000;

/// Sun JKS key store (docs/signature-formats.md, section 14), the container in which some Ukrainian banks issue
/// DSTU 4145 keys. Layout (all integers big-endian): magic FEEDFEED, version 2, entry count, entries, then SHA-1 over
/// the password (UTF-16BE), the string "Mighty Aphrodite" and everything before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JksKeyStore {
    entries: Vec<JksEntry>,
}

impl JksKeyStore {
    /// An empty key store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The entries in stored order.
    pub fn entries(&self) -> &[JksEntry] {
        &self.entries
    }

    /// The private key entries in stored order.
    pub fn private_keys(&self) -> impl Iterator<Item = &JksPrivateKeyEntry> {
        self.entries.iter().filter_map(|entry| match entry {
            JksEntry::PrivateKey(key) => Some(key),
            JksEntry::TrustedCertificate(_) => None,
        })
    }

    /// The entry with this alias, compared ignoring case as Java does.
    pub fn find(&self, alias: &str) -> Option<&JksEntry> {
        self.entries
            .iter()
            .find(|entry| equal_ignoring_case(entry.alias(), alias))
    }

    /// Adds a private key protected with `password`, with its certificate chain (end entity first).
    pub fn add_private_key(
        &mut self,
        alias: &str,
        key: &Dstu4145PrivateKey,
        chain: Vec<Certificate>,
        password: &str,
    ) -> Result<(), KeyStoreError> {
        self.require_free_alias(alias)?;
        let mut pkcs8 = key.to_pkcs8()?;
        let protected_key = key_protector::protect_key(&pkcs8, password);
        pkcs8.fill(0);
        self.entries.push(JksEntry::PrivateKey(JksPrivateKeyEntry {
            alias: alias.to_owned(),
            created: OffsetDateTime::now_utc(),
            protected_key,
            chain,
        }));
        Ok(())
    }

    /// Adds a trusted certificate.
    pub fn add_trusted_certificate(&mut self, alias: &str, certificate: Certificate) -> Result<(), KeyStoreError> {
        self.require_free_alias(alias)?;
        self.entries
            .push(JksEntry::TrustedCertificate(JksTrustedCertificateEntry {
                alias: alias.to_owned(),
                created: OffsetDateTime::now_utc(),
                certificate,
            }));
        Ok(())
    }

    /// Reads a key store after checking its integrity with `password`.
    pub fn load(data: &[u8], password: &str) -> Result<Self, KeyStoreError> {
        if data.len() < MIN_STORE_BYTES {
            return Err(KeyStoreError::TooShort);
        }
        let (body, integrity) = data.split_at(data.len() - SHA1_BYTES);
        let mut reader = JavaReader::new(body);
        if reader.read_u32()? != MAGIC {
            return Err(KeyStoreError::NotJks);
        }
        if !key_protector::equal_in_constant_time(&integrity_hash(body, password), integrity) {
            return Err(KeyStoreError::IntegrityCheckFailed);
        }
        let version = reader.read_u32()?;
        if version != VERSION_1 && version != VERSION_2 {
            return Err(KeyStoreError::UnsupportedVersion { version });
        }
        let count = reader.read_u32()?;
        let mut store = Self::new();
        for _ in 0..count {
            store.entries.push(read_entry(&mut reader, version)?);
        }
        if !reader.is_at_end() {
            return Err(KeyStoreError::TrailingData);
        }
        Ok(store)
    }

    /// The key store as bytes, its integrity hash made with `password`.
    pub fn save(&self, password: &str) -> Result<Vec<u8>, KeyStoreError> {
        let mut body = Vec::new();
        java_data::write_u32(&mut body, MAGIC);
        java_data::write_u32(&mut body, VERSION_2);
        java_data::write_u32(&mut body, self.entries.len() as u32);
        for entry in &self.entries {
            write_entry(&mut body, entry)?;
        }
        let integrity = integrity_hash(&body, password);
        body.extend_from_slice(&integrity);
        Ok(body)
    }

    fn require_free_alias(&self, alias: &str) -> Result<(), KeyStoreError> {
        match self.find(alias) {
            Some(_) => Err(KeyStoreError::DuplicateAlias {
                alias: alias.to_owned(),
            }),
            None => Ok(()),
        }
    }
}

fn read_entry(reader: &mut JavaReader<'_>, version: u32) -> Result<JksEntry, KeyStoreError> {
    let tag = reader.read_u32()?;
    let alias = reader.read_java_utf()?;
    let created = time_of_millis(reader.read_u64()?)?;
    match tag {
        PRIVATE_KEY_TAG => {
            let protected_key = reader.read_counted_bytes()?.to_vec();
            let chain_length = reader.read_u32()?;
            let chain = (0..chain_length)
                .map(|_| read_certificate(reader, version))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(JksEntry::PrivateKey(JksPrivateKeyEntry {
                alias,
                created,
                protected_key,
                chain,
            }))
        }
        TRUSTED_CERTIFICATE_TAG => Ok(JksEntry::TrustedCertificate(JksTrustedCertificateEntry {
            alias,
            created,
            certificate: read_certificate(reader, version)?,
        })),
        _ => Err(KeyStoreError::UnknownEntryType { tag }),
    }
}

fn read_certificate(reader: &mut JavaReader<'_>, version: u32) -> Result<Certificate, KeyStoreError> {
    if version == VERSION_2 {
        let name = reader.read_java_utf()?;
        if name != X509_TYPE {
            return Err(KeyStoreError::UnsupportedCertificateType { name });
        }
    }
    Ok(Certificate::load(reader.read_counted_bytes()?)?)
}

fn write_entry(body: &mut Vec<u8>, entry: &JksEntry) -> Result<(), KeyStoreError> {
    let tag = match entry {
        JksEntry::PrivateKey(_) => PRIVATE_KEY_TAG,
        JksEntry::TrustedCertificate(_) => TRUSTED_CERTIFICATE_TAG,
    };
    java_data::write_u32(body, tag);
    java_data::write_java_utf(body, entry.alias())?;
    let millis = (entry.created().unix_timestamp_nanos() / NANOSECONDS_PER_MILLISECOND) as i64;
    body.extend_from_slice(&millis.to_be_bytes());
    match entry {
        JksEntry::PrivateKey(key) => {
            java_data::write_u32(body, key.protected_key.len() as u32);
            body.extend_from_slice(&key.protected_key);
            java_data::write_u32(body, key.chain.len() as u32);
            for certificate in &key.chain {
                write_certificate(body, certificate)?;
            }
        }
        JksEntry::TrustedCertificate(trusted) => write_certificate(body, &trusted.certificate)?,
    }
    Ok(())
}

fn write_certificate(body: &mut Vec<u8>, certificate: &Certificate) -> Result<(), KeyStoreError> {
    java_data::write_java_utf(body, X509_TYPE)?;
    java_data::write_u32(body, certificate.encoded().len() as u32);
    body.extend_from_slice(certificate.encoded());
    Ok(())
}

// SHA-1(password UTF-16BE ‖ "Mighty Aphrodite" ‖ body).
fn integrity_hash(body: &[u8], password: &str) -> [u8; SHA1_BYTES] {
    let mut password_bytes = key_protector::password_bytes(password);
    let hash = key_protector::sha1_of(&[&password_bytes, INTEGRITY_SALT, body]);
    password_bytes.fill(0);
    hash
}

// Java's milliseconds since the epoch, read as a signed value as Java writes it.
fn time_of_millis(millis: u64) -> Result<OffsetDateTime, KeyStoreError> {
    let nanoseconds = i128::from(millis as i64) * NANOSECONDS_PER_MILLISECOND;
    OffsetDateTime::from_unix_timestamp_nanos(nanoseconds).map_err(|_| KeyStoreError::InvalidCreationTime)
}

fn equal_ignoring_case(a: &str, b: &str) -> bool {
    a.chars()
        .flat_map(char::to_uppercase)
        .eq(b.chars().flat_map(char::to_uppercase))
}
