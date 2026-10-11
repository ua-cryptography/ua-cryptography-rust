//! The Sun JKS key protector (1.3.6.1.4.1.42.2.17.1.1): salt(20) ‖ key XOR keystream ‖ SHA-1(password ‖ key), where
//! keystream block i = SHA-1(password ‖ block i − 1) and block 0 is the salt; the password is UTF-16BE.

use rand_core::{OsRng, RngCore};
use sha1::{Digest, Sha1};
use ua_cryptography_der::{Asn1Node, tag};

use crate::errors::KeyStoreError;
use crate::oids;

/// The bytes of a SHA-1 hash: the salt, a keystream block and the check value.
pub(crate) const SHA1_BYTES: usize = 20;

/// EncryptedPrivateKeyInfo of `pkcs8` under the key protector with a fresh salt.
pub(crate) fn protect_key(pkcs8: &[u8], password: &str) -> Vec<u8> {
    let mut password_bytes = password_bytes(password);
    let mut salt = [0u8; SHA1_BYTES];
    OsRng.fill_bytes(&mut salt);
    let mut stream = key_stream(&password_bytes, &salt, pkcs8.len());
    let mut encrypted = Vec::with_capacity(2 * SHA1_BYTES + pkcs8.len());
    encrypted.extend_from_slice(&salt);
    encrypted.extend(pkcs8.iter().zip(&stream).map(|(byte, key)| byte ^ key));
    encrypted.extend_from_slice(&sha1_of(&[&password_bytes, pkcs8]));
    password_bytes.fill(0);
    stream.fill(0);
    let algorithm = ua_cryptography_der::sequence([
        ua_cryptography_der::object_identifier(oids::JKS_KEY_PROTECTOR),
        ua_cryptography_der::null(),
    ]);
    ua_cryptography_der::sequence([algorithm, ua_cryptography_der::octet_string(&encrypted)])
}

/// The PKCS#8 key inside EncryptedPrivateKeyInfo; refuses another protector or a wrong password.
pub(crate) fn unprotect_key(encrypted_private_key_info: &[u8], password: &str) -> Result<Vec<u8>, KeyStoreError> {
    let info = Asn1Node::parse(encrypted_private_key_info)?.expect_tag(tag::SEQUENCE)?;
    let algorithm = info.child(0)?.child(0)?.to_oid()?;
    if algorithm != oids::JKS_KEY_PROTECTOR {
        return Err(KeyStoreError::UnsupportedKeyProtection { oid: algorithm });
    }
    let encrypted = info.child(1)?.to_octet_string()?;
    if encrypted.len() < 2 * SHA1_BYTES {
        return Err(KeyStoreError::ProtectedKeyTooShort);
    }
    let (salt, rest) = encrypted.split_at(SHA1_BYTES);
    let (masked, check) = rest.split_at(rest.len() - SHA1_BYTES);

    let mut password_bytes = password_bytes(password);
    let mut stream = key_stream(&password_bytes, salt, masked.len());
    let mut key: Vec<u8> = masked.iter().zip(&stream).map(|(byte, key)| byte ^ key).collect();
    let expected = sha1_of(&[&password_bytes, &key]);
    password_bytes.fill(0);
    stream.fill(0);
    if !equal_in_constant_time(&expected, check) {
        key.fill(0);
        return Err(KeyStoreError::WrongKeyPassword);
    }
    Ok(key)
}

/// The password as Java hashes it: UTF-16BE.
pub(crate) fn password_bytes(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

/// SHA-1 of the concatenation of `parts`.
pub(crate) fn sha1_of(parts: &[&[u8]]) -> [u8; SHA1_BYTES] {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Compares without an early exit, so the time does not tell where the first difference is.
pub(crate) fn equal_in_constant_time(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |difference, (x, y)| difference | (x ^ y)) == 0
}

fn key_stream(password_bytes: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let mut stream = Vec::with_capacity(length + SHA1_BYTES);
    let mut previous = salt.to_vec();
    while stream.len() < length {
        previous = sha1_of(&[password_bytes, &previous]).to_vec();
        stream.extend_from_slice(&previous);
    }
    stream.truncate(length);
    stream
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_protected_key_opens_with_its_password_only() {
        let key: Vec<u8> = (0..=60).collect();
        let protected = protect_key(&key, "пароль");
        assert_eq!(unprotect_key(&protected, "пароль").unwrap(), key);
        assert_eq!(unprotect_key(&protected, "parol"), Err(KeyStoreError::WrongKeyPassword));
    }
}
