use crate::FieldError;
use crate::gf2_poly::{self, MAX_PRODUCT_WORDS, MAX_WORDS, WORD_BITS, Words};
use crate::polynomial_basis::{check_degree, is_small_prime};

/// The Gaussian optimal normal basis of type 2 of GF(2^m) (DSTU 4145-2002, В.2, В.4, table 2).
///
/// The standard representation (5.3) lists the coefficients of (x, x², x⁴, …, x^(2^(m−1))) from the most significant
/// bit down: squaring is a cyclic shift right and the unit is all ones. Inside, p = 2m + 1 is prime, x = g + 1/g for a
/// primitive p-th root of unity g, and the basis is a permutation of s_k = g^k + g^(−k), k = 1..m, for which
/// s_i · s_j = s_(i+j) + s_|i−j|. A product is then two carry-less polynomial products, A·B and A·B* with B* the
/// bit reversal of B, and a "folding" of exponents (the "palindromic" representation of Blake, Roth, Seroussi and
/// Wu, Hasan, Blake, Gao). Internally the coefficient of s_k sits at bit k, bit 0 is always zero.
#[derive(Debug, Clone)]
pub struct OptimalNormalBasis {
    m: u32,
    words: usize,
    /// position[i] = the internal bit that holds the coefficient of x^(2^i).
    position: Vec<u16>,
    /// The inverse map: internal bit k → i.
    exponent_of_position: Vec<u16>,
}

impl OptimalNormalBasis {
    /// The degrees of table 2 of DSTU 4145-2002.
    pub const STANDARD_DEGREES: [u32; 14] = [173, 179, 191, 233, 239, 251, 281, 293, 359, 419, 431, 443, 491, 509];

    pub(crate) fn new(m: u32) -> Result<Self, FieldError> {
        check_degree(m)?;
        if !Self::has_type_two_basis(m) {
            return Err(FieldError::NoTypeTwoBasis(m));
        }

        let p = 2 * m + 1;
        let mut position = vec![0u16; m as usize];
        let mut exponent_of_position = vec![0u16; m as usize + 1];
        let mut power = 1u32;
        for (i, slot) in position.iter_mut().enumerate() {
            let k = if power <= m { power } else { p - power };
            *slot = k as u16;
            exponent_of_position[k as usize] = i as u16;
            power = 2 * power % p;
        }
        Ok(Self {
            m,
            words: (m as usize + 1).div_ceil(WORD_BITS),
            position,
            exponent_of_position,
        })
    }

    /// Whether p = 2m + 1 is prime and the order k of 2 modulo p is 2m (2 is primitive), or p ≡ 3 (mod 4) and k = m.
    ///
    /// В.2 states the first case as "p ≡ 1 (mod 4) and k = 2m", which is too strict: for m = 173, the degree of the
    /// standard's own example Б.2, p = 347 ≡ 3 (mod 4) and k = 2m. A type 2 basis exists whenever 2 is primitive
    /// modulo p (Mullin et al., ref. 11 of the standard).
    pub fn has_type_two_basis(m: u32) -> bool {
        let p = 2 * u64::from(m) + 1;
        if m < 2 || !is_small_prime(p as u32) {
            return false;
        }
        let mut order = 1u64;
        let mut v = 2u64;
        while v != 1 {
            v = v * 2 % p;
            order += 1;
        }
        order == 2 * u64::from(m) || (p % 4 == 3 && order == u64::from(m))
    }

    /// Extension degree m.
    pub fn m(&self) -> u32 {
        self.m
    }

    pub(crate) fn words(&self) -> usize {
        self.words
    }

    /// 1 = the sum of all basis elements (5.3): every s_1..s_m.
    pub(crate) fn one(&self) -> Words {
        let mut one: Words = [0; MAX_WORDS];
        for k in 1..=self.m as usize {
            gf2_poly::flip_bit(&mut one, k);
        }
        one
    }

    pub(crate) fn internal_from_standard(&self, standard: &Words) -> Words {
        let m = self.m as usize;
        let mut internal: Words = [0; MAX_WORDS];
        // Standard bit j is the coefficient of x^(2^(m−1−j)).
        for j in 0..m {
            if gf2_poly::test_bit(standard, j) {
                gf2_poly::flip_bit(&mut internal, usize::from(self.position[m - 1 - j]));
            }
        }
        internal
    }

    pub(crate) fn standard_from_internal(&self, internal: &Words) -> Words {
        let m = self.m as usize;
        let mut standard: Words = [0; MAX_WORDS];
        for k in 1..=m {
            if gf2_poly::test_bit(internal, k) {
                gf2_poly::flip_bit(&mut standard, m - 1 - usize::from(self.exponent_of_position[k]));
            }
        }
        standard
    }

    pub(crate) fn multiply(&self, a: &Words, b: &Words) -> Words {
        let (w, m) = (self.words, self.m as usize);
        let mut b_reflected: Words = [0; MAX_WORDS];
        let mut p1 = [0u64; MAX_PRODUCT_WORDS];
        let mut p2 = [0u64; MAX_PRODUCT_WORDS];

        // a = Σ a_i s_i, b = Σ b_j s_j, i, j in 1..m.
        // P1 = A(t) B(t):  the coefficient of t^(i+j)     → s_(i+j)
        // P2 = A(t) B*(t): the coefficient of t^(m+1+i−j) → s_|i−j|   (B*(t) = t^(m+1) B(1/t))
        self.reflect(&b[..w], &mut b_reflected[..w]);
        gf2_poly::multiply(&a[..w], &b[..w], &mut p1[..2 * w]);
        gf2_poly::multiply(&a[..w], &b_reflected[..w], &mut p2[..2 * w]);

        // Exponents that land on s_u with u = m+1−e after folding:
        //   P1, e = i+j−m in 1..m (s_(i+j) = s_(p−i−j) when i+j > m); P2, e = m+1+i−j in 2..m (i < j).
        let mut high: Words = [0; MAX_WORDS];
        gf2_poly::shift_right(&p1[..2 * w], m, &mut high[..w]);
        gf2_poly::xor_into(&mut high[..w], &p2[..w]);
        self.keep_bits_one_to_m(&mut high);
        let mut folded: Words = [0; MAX_WORDS];
        self.reflect(&high[..w], &mut folded[..w]);

        // Exponents that land directly: P1, i+j ≤ m; P2, m+1+i−j > m+1 → s_(i−j).
        let mut r: Words = [0; MAX_WORDS];
        gf2_poly::shift_right(&p2[..2 * w], m + 1, &mut r[..w]);
        gf2_poly::xor_into(&mut r[..w], &p1[..w]);
        gf2_poly::xor_into(&mut r[..w], &folded[..w]);
        self.keep_bits_one_to_m(&mut r);
        r
    }

    /// s_k² = s_2k; exponents 2k > m fold to p − 2k.
    pub(crate) fn square(&self, a: &Words) -> Words {
        let (w, m) = (self.words, self.m as usize);
        let mut spread = [0u64; MAX_PRODUCT_WORDS];
        gf2_poly::square(&a[..w], &mut spread[..2 * w]);

        let mut high: Words = [0; MAX_WORDS];
        gf2_poly::shift_right(&spread[..2 * w], m, &mut high[..w]);
        self.keep_bits_one_to_m(&mut high);
        let mut folded: Words = [0; MAX_WORDS];
        self.reflect(&high[..w], &mut folded[..w]);

        let mut r: Words = [0; MAX_WORDS];
        r[..w].copy_from_slice(&spread[..w]);
        gf2_poly::xor_into(&mut r[..w], &folded[..w]);
        self.keep_bits_one_to_m(&mut r);
        r
    }

    /// dst bit (m+1−u) = src bit u for u = 1..m; src has bit 0 and the bits above m cleared.
    fn reflect(&self, src: &[u64], dst: &mut [u64]) {
        let w = self.words;
        let mut reversed: Words = [0; MAX_WORDS];
        gf2_poly::reverse_words(&src[..w], &mut reversed[..w]); // bit u → 64w − 1 − u
        // Move 64w − 1 − u to m + 1 − u.
        let shift = (WORD_BITS * w) as i64 - 2 - i64::from(self.m);
        if shift >= 0 {
            gf2_poly::shift_right(&reversed[..w], shift as usize, &mut dst[..w]);
        } else {
            gf2_poly::shift_left(&reversed[..w], (-shift) as usize, &mut dst[..w]);
        }
    }

    fn keep_bits_one_to_m(&self, a: &mut Words) {
        a[0] &= !1;
        gf2_poly::clear_above(&mut a[..self.words], self.m as usize + 1);
    }
}

impl PartialEq for OptimalNormalBasis {
    fn eq(&self, other: &Self) -> bool {
        self.m == other.m
    }
}

impl Eq for OptimalNormalBasis {}
