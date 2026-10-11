//! DSTU 7624:2014 "Kalyna" and its modes. `block_bits` is 128, 256 or 512; the key is one or two blocks long
//! (128/128, 128/256, 256/256, 256/512, 512/512).

use ua_cryptography_dstu7624::{BlockSize, Cbc, Ccm, Cfb, Cmac, Ctr, Ecb, Gcm, Gmac, Kalyna, KeyWrap, Ofb, Xts};

use crate::errors::OperationFailure;

/// Encrypts one block.
pub fn encrypt_block(block_bits: u32, key: &[u8], block: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    let cipher = create_cipher(block_bits, key, block)?;
    let mut result = block.to_vec();
    cipher.encrypt_block(&mut result);
    Ok(result)
}

/// Decrypts one block.
pub fn decrypt_block(block_bits: u32, key: &[u8], block: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    let cipher = create_cipher(block_bits, key, block)?;
    let mut result = block.to_vec();
    cipher.decrypt_block(&mut result);
    Ok(result)
}

/// ECB ("простої заміни"): whole blocks.
pub fn ecb_encrypt(block_bits: u32, key: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(Ecb::new(read_block_size(block_bits)?, key)?.encrypt(data)?)
}

/// ECB decryption.
pub fn ecb_decrypt(block_bits: u32, key: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(Ecb::new(read_block_size(block_bits)?, key)?.decrypt(data)?)
}

/// CBC ("простої заміни з зачепленням"): whole blocks, an IV of one block.
pub fn cbc_encrypt(block_bits: u32, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(Cbc::new(read_block_size(block_bits)?, key)?.encrypt(iv, data)?)
}

/// CBC decryption.
pub fn cbc_decrypt(block_bits: u32, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(Cbc::new(read_block_size(block_bits)?, key)?.decrypt(iv, data)?)
}

/// CFB ("гамування зі зворотним зв'язком за шифрограмою") with a segment of `segment_bits` (a block when absent).
pub fn cfb_encrypt(
    block_bits: u32,
    key: &[u8],
    segment_bits: Option<u32>,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, OperationFailure> {
    Ok(create_cfb(block_bits, key, segment_bits)?.encrypt(iv, data)?)
}

/// CFB decryption.
pub fn cfb_decrypt(
    block_bits: u32,
    key: &[u8],
    segment_bits: Option<u32>,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, OperationFailure> {
    Ok(create_cfb(block_bits, key, segment_bits)?.decrypt(iv, data)?)
}

/// OFB ("гамування зі зворотним зв'язком за гамою"): encryption and decryption are the same.
pub fn ofb_apply_gamma(
    block_bits: u32,
    key: &[u8],
    segment_bits: Option<u32>,
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, OperationFailure> {
    let block_size = read_block_size(block_bits)?;
    let ofb = match segment_bits {
        Some(segment_bits) => Ofb::with_segment(block_size, key, segment_bits as usize)?,
        None => Ofb::new(block_size, key)?,
    };
    Ok(ofb.apply_gamma(iv, data)?)
}

/// CTR ("гамування"): encryption and decryption are the same.
pub fn ctr_apply_gamma(block_bits: u32, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(Ctr::new(read_block_size(block_bits)?, key)?.apply_gamma(iv, data)?)
}

/// CMAC ("вироблення імітовставки") of `mac_bits` over a non-empty whole number of blocks.
pub fn cmac_calculate_mac(
    block_bits: u32,
    key: &[u8],
    mac_bits: u32,
    data: &[u8],
) -> Result<Vec<u8>, OperationFailure> {
    Ok(Cmac::new(read_block_size(block_bits)?, key, mac_bits as usize)?.calculate_mac(data)?)
}

/// CCM: ciphertext ‖ tag of `mac_bits`; the length field Nb is 4, 6 or 8 bytes (4 when absent).
pub fn ccm_encrypt(
    block_bits: u32,
    key: &[u8],
    nb: Option<u32>,
    nonce: &[u8],
    associated_data: &[u8],
    plain_text: &[u8],
    mac_bits: u32,
) -> Result<Vec<u8>, OperationFailure> {
    Ok(create_ccm(block_bits, key, nb)?.encrypt(nonce, associated_data, plain_text, mac_bits as usize)?)
}

/// CCM: verifies the tag of ciphertext ‖ tag and decrypts.
pub fn ccm_decrypt(
    block_bits: u32,
    key: &[u8],
    nb: Option<u32>,
    nonce: &[u8],
    associated_data: &[u8],
    cipher_text: &[u8],
    mac_bits: u32,
) -> Result<Vec<u8>, OperationFailure> {
    Ok(create_ccm(block_bits, key, nb)?.decrypt(nonce, associated_data, cipher_text, mac_bits as usize)?)
}

/// GCM: ciphertext ‖ tag of `mac_bits`.
pub fn gcm_encrypt(
    block_bits: u32,
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    plain_text: &[u8],
    mac_bits: u32,
) -> Result<Vec<u8>, OperationFailure> {
    let gcm = Gcm::new(read_block_size(block_bits)?, key)?;
    Ok(gcm.encrypt(nonce, associated_data, plain_text, mac_bits as usize)?)
}

/// GCM: verifies the tag of ciphertext ‖ tag and decrypts.
pub fn gcm_decrypt(
    block_bits: u32,
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    cipher_text: &[u8],
    mac_bits: u32,
) -> Result<Vec<u8>, OperationFailure> {
    let gcm = Gcm::new(read_block_size(block_bits)?, key)?;
    Ok(gcm.decrypt(nonce, associated_data, cipher_text, mac_bits as usize)?)
}

/// GMAC of `mac_bits` over `data` under `nonce`.
pub fn gmac_calculate_mac(
    block_bits: u32,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
    mac_bits: u32,
) -> Result<Vec<u8>, OperationFailure> {
    Ok(Gmac::new(read_block_size(block_bits)?, key)?.calculate_mac(nonce, data, mac_bits as usize)?)
}

/// XTS ("індексована заміна"): whole blocks under the tweak IV of one block.
pub fn xts_encrypt(block_bits: u32, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(Xts::new(read_block_size(block_bits)?, key)?.encrypt(iv, data)?)
}

/// XTS decryption.
pub fn xts_decrypt(block_bits: u32, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(Xts::new(read_block_size(block_bits)?, key)?.decrypt(iv, data)?)
}

/// KW ("захист ключів"): wraps a non-empty whole number of blocks into one block more.
pub fn wrap_key(block_bits: u32, key: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(KeyWrap::new(read_block_size(block_bits)?, key)?.wrap_key(data)?)
}

/// KW: unwraps and checks the integrity block.
pub fn unwrap_key(block_bits: u32, key: &[u8], data: &[u8]) -> Result<Vec<u8>, OperationFailure> {
    Ok(KeyWrap::new(read_block_size(block_bits)?, key)?.unwrap_key(data)?)
}

fn read_block_size(block_bits: u32) -> Result<BlockSize, OperationFailure> {
    Ok(BlockSize::from_bits(block_bits as usize)?)
}

// Kalyna panics on a block of another length: refuse it first.
fn create_cipher(block_bits: u32, key: &[u8], block: &[u8]) -> Result<Kalyna, OperationFailure> {
    let cipher = Kalyna::new(read_block_size(block_bits)?, key)?;
    if block.len() != cipher.block_bytes() {
        return Err(OperationFailure::invalid_argument(format!(
            "A Kalyna block is {} bytes, not {}.",
            cipher.block_bytes(),
            block.len()
        )));
    }
    Ok(cipher)
}

fn create_cfb(block_bits: u32, key: &[u8], segment_bits: Option<u32>) -> Result<Cfb, OperationFailure> {
    let block_size = read_block_size(block_bits)?;
    match segment_bits {
        Some(segment_bits) => Ok(Cfb::with_segment(block_size, key, segment_bits as usize)?),
        None => Ok(Cfb::new(block_size, key)?),
    }
}

fn create_ccm(block_bits: u32, key: &[u8], nb: Option<u32>) -> Result<Ccm, OperationFailure> {
    let block_size = read_block_size(block_bits)?;
    match nb {
        Some(nb) => Ok(Ccm::with_nb(block_size, key, nb as usize)?),
        None => Ok(Ccm::new(block_size, key)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::FailureKind;

    const KEY: [u8; 32] = [3; 32];
    const IV: [u8; 16] = [5; 16];

    #[test]
    fn every_mode_decrypts_what_it_encrypted() {
        let data: Vec<u8> = (0..32).collect();
        let block = &data[..16];
        assert_eq!(
            decrypt_block(128, &KEY, &encrypt_block(128, &KEY, block).unwrap()).unwrap(),
            block
        );
        assert_eq!(
            ecb_decrypt(128, &KEY, &ecb_encrypt(128, &KEY, &data).unwrap()).unwrap(),
            data
        );
        assert_eq!(
            cbc_decrypt(128, &KEY, &IV, &cbc_encrypt(128, &KEY, &IV, &data).unwrap()).unwrap(),
            data
        );
        let cfb = cfb_encrypt(128, &KEY, Some(8), &IV, &data).unwrap();
        assert_eq!(cfb_decrypt(128, &KEY, Some(8), &IV, &cfb).unwrap(), data);
        let ofb = ofb_apply_gamma(128, &KEY, None, &IV, &data).unwrap();
        assert_eq!(ofb_apply_gamma(128, &KEY, None, &IV, &ofb).unwrap(), data);
        let ctr = ctr_apply_gamma(128, &KEY, &IV, &data).unwrap();
        assert_eq!(ctr_apply_gamma(128, &KEY, &IV, &ctr).unwrap(), data);
        let ccm = ccm_encrypt(128, &KEY, None, &IV, b"header", &data, 128).unwrap();
        assert_eq!(
            ccm_decrypt(128, &KEY, Some(4), &IV, b"header", &ccm, 128).unwrap(),
            data
        );
        let gcm = gcm_encrypt(128, &KEY, &IV, b"header", &data, 128).unwrap();
        assert_eq!(gcm_decrypt(128, &KEY, &IV, b"header", &gcm, 128).unwrap(), data);
        assert_eq!(
            xts_decrypt(128, &KEY, &IV, &xts_encrypt(128, &KEY, &IV, &data).unwrap()).unwrap(),
            data
        );
        assert_eq!(
            unwrap_key(128, &KEY, &wrap_key(128, &KEY, &data).unwrap()).unwrap(),
            data
        );
    }

    #[test]
    fn the_macs_have_the_length_asked() {
        let data = [9u8; 32];
        assert_eq!(cmac_calculate_mac(128, &KEY, 64, &data).unwrap().len(), 8);
        assert_eq!(gmac_calculate_mac(128, &KEY, &IV, &data, 128).unwrap().len(), 16);
    }

    #[test]
    fn a_forged_tag_is_an_authentication_failure() {
        let mut sealed = gcm_encrypt(256, &KEY, &IV, b"", b"secret", 128).unwrap();
        sealed[0] ^= 1;
        let failure = gcm_decrypt(256, &KEY, &IV, b"", &sealed, 128).unwrap_err();
        assert_eq!(failure.kind, FailureKind::AuthenticationFailed);
    }

    #[test]
    fn a_block_of_another_length_is_refused_not_a_panic() {
        assert!(encrypt_block(128, &KEY, &[0; 15]).is_err());
        assert!(ecb_encrypt(192, &KEY, &[0; 16]).is_err());
    }
}
