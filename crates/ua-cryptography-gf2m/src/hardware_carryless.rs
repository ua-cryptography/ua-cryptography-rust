//! Carry-less multiplication by PMULL (ARMv8 Crypto) or PCLMULQDQ (x86-64), the one place with `unsafe` code.
//!
//! A [`CarrylessUnit`] exists only after the CPU feature was detected at run time, so calling the
//! `#[target_feature]` functions through it is sound.

/// Proof that this CPU has a carry-less multiplication instruction.
#[derive(Clone, Copy)]
pub(crate) struct CarrylessUnit(());

/// The unit, when the CPU supports it.
pub(crate) fn detect() -> Option<CarrylessUnit> {
    if is_supported() { Some(CarrylessUnit(())) } else { None }
}

impl CarrylessUnit {
    /// r = a · b in GF(2)[x]; r must hold exactly `a.len() + b.len()` words.
    ///
    /// Product scanning: output word k collects lo(a_i b_j) for i + j = k and hi(a_i b_j) for i + j = k − 1,
    /// so the partial products stay in registers and r is written once.
    pub(crate) fn multiply(self, a: &[u64], b: &[u64], r: &mut [u64]) {
        assert_eq!(r.len(), a.len() + b.len(), "the product needs a.len() + b.len() words");
        if a.is_empty() || b.is_empty() {
            r.fill(0);
            return;
        }
        // SAFETY: a CarrylessUnit is only created by `detect` after the CPU feature check.
        unsafe { multiply_scanning(a, b, r) }
    }
}

#[cfg(target_arch = "aarch64")]
fn is_supported() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
}

#[cfg(target_arch = "x86_64")]
fn is_supported() -> bool {
    std::arch::is_x86_feature_detected!("pclmulqdq")
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
fn is_supported() -> bool {
    false
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,aes")]
unsafe fn multiply_scanning(a: &[u64], b: &[u64], r: &mut [u64]) {
    use std::arch::aarch64::vmull_p64;

    let (a_len, b_len) = (a.len(), b.len());
    let mut carried_high = 0u64;
    for k in 0..a_len + b_len - 1 {
        let first = (k + 1).saturating_sub(b_len);
        let last = k.min(a_len - 1);
        let mut accumulator: u128 = 0;
        for i in first..=last {
            accumulator ^= vmull_p64(a[i], b[k - i]);
        }
        r[k] = (accumulator as u64) ^ carried_high;
        carried_high = (accumulator >> 64) as u64;
    }
    r[a_len + b_len - 1] = carried_high;
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
unsafe fn multiply_scanning(a: &[u64], b: &[u64], r: &mut [u64]) {
    use std::arch::x86_64::{
        _mm_clmulepi64_si128, _mm_cvtsi64_si128, _mm_cvtsi128_si64, _mm_setzero_si128, _mm_unpackhi_epi64,
        _mm_xor_si128,
    };
    const LOW_BY_LOW: i32 = 0x00;

    let (a_len, b_len) = (a.len(), b.len());
    let mut carried_high = 0u64;
    for k in 0..a_len + b_len - 1 {
        let first = (k + 1).saturating_sub(b_len);
        let last = k.min(a_len - 1);
        let mut accumulator = _mm_setzero_si128();
        for i in first..=last {
            let x = _mm_cvtsi64_si128(a[i] as i64);
            let y = _mm_cvtsi64_si128(b[k - i] as i64);
            accumulator = _mm_xor_si128(accumulator, _mm_clmulepi64_si128::<LOW_BY_LOW>(x, y));
        }
        r[k] = (_mm_cvtsi128_si64(accumulator) as u64) ^ carried_high;
        carried_high = _mm_cvtsi128_si64(_mm_unpackhi_epi64(accumulator, accumulator)) as u64;
    }
    r[a_len + b_len - 1] = carried_high;
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
unsafe fn multiply_scanning(_a: &[u64], _b: &[u64], _r: &mut [u64]) {
    unreachable!("no carry-less multiplication instruction on this architecture")
}
