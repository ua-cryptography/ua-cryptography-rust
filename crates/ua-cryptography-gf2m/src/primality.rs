//! Integer checks of the domain parameters (DSTU 4145-2002, 6.12).

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand_core::{CryptoRng, RngCore};

/// Rounds of the Miller–Rabin test that 6.12 prescribes.
pub const STANDARD_PRIMALITY_ROUNDS: u32 = 50;

const SMALL_PRIMES: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
const SMALLEST_BASE: u32 = 2;
const BYTE_BITS: u64 = 8;

/// Miller–Rabin test with `rounds` random bases (DSTU 4145-2002, 6.12).
pub fn is_probable_prime(n: &BigUint, rounds: u32, rng: &mut (impl RngCore + CryptoRng)) -> bool {
    if *n < BigUint::from(SMALLEST_BASE) {
        return false;
    }
    for small in SMALL_PRIMES {
        if *n == BigUint::from(small) {
            return true;
        }
        if (n % small).is_zero() {
            return false;
        }
    }

    // n − 1 = j · 2^k, j odd
    let n_minus_one = n - 1u32;
    let Some(k) = n_minus_one.trailing_zeros() else {
        return false; // n − 1 > 0 here
    };
    let j = &n_minus_one >> k;
    (0..rounds).all(|_| passes_round(n, &n_minus_one, &j, k, &random_base(n, rng)))
}

/// ⌊√n⌋.
pub fn integer_sqrt(n: &BigUint) -> BigUint {
    n.sqrt()
}

/// One Miller–Rabin round with base a: true when n may be prime.
fn passes_round(n: &BigUint, n_minus_one: &BigUint, j: &BigUint, k: u64, a: &BigUint) -> bool {
    let mut b = a.modpow(j, n);
    if b.is_one() || b == *n_minus_one {
        return true;
    }
    for _ in 1..k {
        b = &b * &b % n;
        if b == *n_minus_one {
            return true;
        }
        if b.is_one() {
            return false;
        }
    }
    false
}

/// A random base 2 ≤ a < n: random bytes of the length of n, reduced mod n.
fn random_base(n: &BigUint, rng: &mut (impl RngCore + CryptoRng)) -> BigUint {
    let mut buffer = vec![0u8; n.bits().div_ceil(BYTE_BITS) as usize];
    loop {
        rng.fill_bytes(&mut buffer);
        let a = BigUint::from_bytes_le(&buffer) % n;
        if a >= BigUint::from(SMALLEST_BASE) {
            return a;
        }
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn small_primes_and_composites_are_told_apart() {
        let primes: Vec<u32> = (0..200u32)
            .filter(|&n| is_probable_prime(&BigUint::from(n), STANDARD_PRIMALITY_ROUNDS, &mut OsRng))
            .collect();
        let expected: Vec<u32> = (2..200u32).filter(|&n| (2..n).all(|d| n % d != 0)).collect();
        assert_eq!(expected, primes);
    }

    #[test]
    fn a_mersenne_prime_passes_and_a_carmichael_number_fails() {
        let mersenne = (BigUint::one() << 127u32) - 1u32;
        assert!(is_probable_prime(&mersenne, STANDARD_PRIMALITY_ROUNDS, &mut OsRng));
        let carmichael = BigUint::from(41u32 * 101 * 241 * 1009);
        assert!(!is_probable_prime(&carmichael, STANDARD_PRIMALITY_ROUNDS, &mut OsRng));
    }

    #[test]
    fn integer_square_root_rounds_down() {
        assert_eq!(BigUint::from(3u32), integer_sqrt(&BigUint::from(15u32)));
        assert_eq!(BigUint::from(4u32), integer_sqrt(&BigUint::from(16u32)));
        assert_eq!(BigUint::one() << 80u32, integer_sqrt(&(BigUint::one() << 160u32)));
    }
}
