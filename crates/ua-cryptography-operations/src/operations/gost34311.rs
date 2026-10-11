//! GOST 34.311-95 with any DKE and initial value.

use ua_cryptography_gost::{DEFAULT_DKE, Gost28147, Gost34311};

use crate::errors::OperationFailure;

/// The 32-byte hash H as GOST defines it, least significant byte first (reverse it for DSTU 4145, 5.9).
pub fn calculate_hash(
    data: &[u8],
    dke: Option<&[u8]>,
    initial_value: Option<&[u8]>,
) -> Result<Vec<u8>, OperationFailure> {
    Ok(create_hash(dke, initial_value)?.hash(data).to_vec())
}

/// The hash over the 64-byte `dke` (DKE No. 1 when absent) from the 32-byte `initial_value` (zero when absent).
pub fn create_hash(dke: Option<&[u8]>, initial_value: Option<&[u8]>) -> Result<Gost34311, OperationFailure> {
    let dke = match dke {
        Some(dke) => dke,
        None => &DEFAULT_DKE,
    };
    let sbox = Gost28147::expand_dke(dke)?;
    match initial_value {
        None => Ok(Gost34311::new(&sbox)?),
        Some(initial_value) => {
            let initial_value: &[u8; Gost34311::HASH_BYTES] = initial_value.try_into().map_err(|_| {
                OperationFailure::invalid_argument(format!(
                    "The GOST 34.311 initial value is {} bytes, not {}.",
                    Gost34311::HASH_BYTES,
                    initial_value.len()
                ))
            })?;
            Ok(Gost34311::with_initial_value(&sbox, initial_value)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_dke_no_1_and_a_zero_initial_value() {
        let expected = Gost34311::calculate_hash(b"message").to_vec();
        assert_eq!(calculate_hash(b"message", None, None).unwrap(), expected);
        assert_eq!(
            calculate_hash(b"message", Some(&DEFAULT_DKE), Some(&[0; 32])).unwrap(),
            expected
        );
    }

    #[test]
    fn a_dke_of_another_length_is_refused() {
        assert!(calculate_hash(b"message", Some(&[0; 63]), None).is_err());
        assert!(calculate_hash(b"message", None, Some(&[0; 31])).is_err());
    }
}
