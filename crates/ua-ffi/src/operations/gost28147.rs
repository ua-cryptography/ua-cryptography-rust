//! GOST 28147-89 in simple substitution mode ("простої заміни") over whole 64-bit blocks.

use ua_gost::{DEFAULT_DKE, Gost28147};

use crate::errors::OperationFailure;

/// Encrypts whole blocks under the 256-bit `key`; `dke` is the 64-byte table, DKE No. 1 when absent.
pub fn encrypt(key: &[u8], dke: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    let cipher = create_cipher(key, dke)?;
    transform_blocks(data, |block| cipher.encrypt_block(block))
}

/// Decrypts whole blocks under the 256-bit `key`; `dke` is the 64-byte table, DKE No. 1 when absent.
pub fn decrypt(key: &[u8], dke: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    let cipher = create_cipher(key, dke)?;
    transform_blocks(data, |block| cipher.decrypt_block(block))
}

fn create_cipher(key: &[u8], dke: Option<&[u8]>) -> Result<Gost28147, OperationFailure> {
    let key: &[u8; Gost28147::KEY_BYTES] = key.try_into().map_err(|_| {
        OperationFailure::invalid_argument(format!(
            "A GOST 28147 key is {} bytes, not {}.",
            Gost28147::KEY_BYTES,
            key.len()
        ))
    })?;
    let dke = match dke {
        Some(dke) => dke,
        None => &DEFAULT_DKE,
    };
    let mut cipher = Gost28147::new(&Gost28147::expand_dke(dke)?)?;
    cipher.set_key(key);
    Ok(cipher)
}

fn transform_blocks(
    data: &[u8],
    transform: impl Fn(&[u8; Gost28147::BLOCK_BYTES]) -> [u8; Gost28147::BLOCK_BYTES],
) -> Result<Vec<u8>, OperationFailure> {
    if data.len() % Gost28147::BLOCK_BYTES != 0 {
        return Err(OperationFailure::invalid_argument(format!(
            "GOST 28147 in simple substitution mode takes whole {}-byte blocks; {} bytes given.",
            Gost28147::BLOCK_BYTES,
            data.len()
        )));
    }
    let mut result = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(Gost28147::BLOCK_BYTES) {
        let mut block = [0u8; Gost28147::BLOCK_BYTES];
        block.copy_from_slice(chunk);
        result.extend_from_slice(&transform(&block));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn decryption_restores_what_encryption_made() {
        let data: Vec<u8> = (0..24).collect();
        let cipher_text = encrypt(&KEY, None, &data).unwrap();
        assert_ne!(cipher_text, data);
        assert_eq!(decrypt(&KEY, None, &cipher_text).unwrap(), data);
    }

    #[test]
    fn the_default_table_is_dke_no_1() {
        let data = [1u8; 8];
        assert_eq!(encrypt(&KEY, None, &data), encrypt(&KEY, Some(&DEFAULT_DKE), &data));
    }

    #[test]
    fn a_partial_block_and_a_short_key_are_refused() {
        assert!(encrypt(&KEY, None, &[0; 7]).is_err());
        assert!(encrypt(&KEY[..31], None, &[0; 8]).is_err());
    }
}
