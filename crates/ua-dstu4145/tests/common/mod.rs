//! Deterministic test data and the recommended curves.

#![allow(dead_code)] // each test binary uses its own part

use num_bigint::BigUint;

/// SplitMix64: a reproducible source of test integers.
pub struct TestRandom(u64);

impl TestRandom {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_word(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A non-negative integer of at most `bits` bits.
    pub fn integer(&mut self, bits: u32) -> BigUint {
        let words: Vec<u64> = (0..bits.div_ceil(64)).map(|_| self.next_word()).collect();
        let mut digits: Vec<u32> = words.iter().flat_map(|&w| [w as u32, (w >> 32) as u32]).collect();
        digits.push(0);
        BigUint::new(digits) & ((BigUint::from(1u32) << bits) - 1u32)
    }
}

/// The 15 recommended curves of Appendix Г: ("PB", m) for table Г.1, ("ONB", m) for table Г.2.
pub fn recommended_curves() -> Vec<(&'static str, u32)> {
    let polynomial = ua_dstu4145::POLYNOMIAL_DEGREES.iter().map(|&m| ("PB", m));
    let normal = ua_dstu4145::NORMAL_DEGREES.iter().map(|&m| ("ONB", m));
    polynomial.chain(normal).collect()
}

pub fn get_recommended_curve(basis: &str, m: u32) -> ua_dstu4145::DomainParameters {
    if basis == "PB" {
        ua_dstu4145::get_polynomial_curve(m).unwrap()
    } else {
        ua_dstu4145::get_optimal_normal_curve(m).unwrap()
    }
}
