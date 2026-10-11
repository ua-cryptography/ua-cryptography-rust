use crate::FieldError;
use crate::gf2_poly::{self, MAX_PRODUCT_WORDS, MAX_WORDS, WORD_BITS, Words};

/// The largest degree the fixed-size arithmetic holds, in either basis.
pub const MAX_DEGREE: u32 = 511;

const MIN_DEGREE: u32 = 2;
const MAX_TERMS: usize = 4;
/// The polynomial t, whose powers t^(2^m) = t test irreducibility.
const POLYNOMIAL_T: u64 = 0b10;

/// The polynomial basis of GF(2^m) given by a trinomial t^m + t^k + 1 or a pentanomial
/// t^m + t^l + t^j + t^k + 1, 0 < k < j < l < m (DSTU 4145-2002, 5.2, table 1).
///
/// Elements are stored exactly as in the standard: bit i is the coefficient of t^i. Multiplication is a carry-less
/// product followed by word-level reduction (В.3).
#[derive(Debug, Clone)]
pub struct PolynomialBasis {
    m: u32,
    k: u32,
    j: u32,
    l: u32,
    /// Exponents of the reduction polynomial below m, including 0.
    terms: [usize; MAX_TERMS],
    term_count: usize,
    words: usize,
}

impl PolynomialBasis {
    /// `j = l = 0` stands for a trinomial.
    pub(crate) fn new(m: u32, k: u32, j: u32, l: u32) -> Result<Self, FieldError> {
        check_degree(m)?;
        if k == 0 || k >= m {
            return Err(FieldError::ExponentOutOfRange { m, k });
        }
        let is_trinomial = j == 0 && l == 0;
        let is_ordered_pentanomial = k < j && j < l && l < m;
        if !is_trinomial && !is_ordered_pentanomial {
            return Err(FieldError::PentanomialNotOrdered { k, j, l });
        }

        // Word-level reduction folds a whole word below position m in one step; this needs the middle terms well
        // below m, which holds for every polynomial of table 1.
        let highest = if is_trinomial { k } else { l };
        if i64::from(highest) > i64::from(m) - WORD_BITS as i64 {
            return Err(FieldError::MiddleTermsTooHigh { m, highest });
        }

        let (terms, term_count) = if is_trinomial {
            ([0, k as usize, 0, 0], 2)
        } else {
            ([0, k as usize, j as usize, l as usize], 4)
        };
        Ok(Self {
            m,
            k,
            j,
            l,
            terms,
            term_count,
            words: (m as usize).div_ceil(WORD_BITS),
        })
    }

    /// Extension degree m.
    pub fn m(&self) -> u32 {
        self.m
    }

    /// The smallest non-zero exponent k.
    pub fn k(&self) -> u32 {
        self.k
    }

    /// The middle exponent j of a pentanomial, 0 for a trinomial.
    pub fn j(&self) -> u32 {
        self.j
    }

    /// The largest exponent l below m of a pentanomial, 0 for a trinomial.
    pub fn l(&self) -> u32 {
        self.l
    }

    /// Whether the reduction polynomial is a trinomial.
    pub fn is_trinomial(&self) -> bool {
        self.j == 0
    }

    /// Whether the reduction polynomial is irreducible, by Rabin's test: for prime m it is enough that
    /// t^(2^m) = t mod f(t), since f has no roots in GF(2) by construction.
    ///
    /// # Panics
    ///
    /// When m is not prime: the quick test does not apply.
    pub fn is_irreducible(&self) -> bool {
        assert!(
            is_small_prime(self.m),
            "the quick irreducibility test requires a prime m, got {}",
            self.m
        );
        let mut t: Words = [0; MAX_WORDS];
        t[0] = POLYNOMIAL_T;
        let mut x = t;
        for _ in 0..self.m {
            x = self.square(&x);
        }
        x == t
    }

    pub(crate) fn words(&self) -> usize {
        self.words
    }

    pub(crate) fn multiply(&self, a: &Words, b: &Words) -> Words {
        let w = self.words;
        let mut product = [0u64; MAX_PRODUCT_WORDS];
        gf2_poly::multiply(&a[..w], &b[..w], &mut product[..2 * w]);
        self.reduce(&mut product)
    }

    pub(crate) fn square(&self, a: &Words) -> Words {
        let w = self.words;
        let mut product = [0u64; MAX_PRODUCT_WORDS];
        gf2_poly::square(&a[..w], &mut product[..2 * w]);
        self.reduce(&mut product)
    }

    /// c mod f(t) for a product c of `2 · words` words.
    fn reduce(&self, c: &mut [u64; MAX_PRODUCT_WORDS]) -> Words {
        let m = self.m as usize;
        let top = m / WORD_BITS; // the word that holds bit m
        let shift = m % WORD_BITS;
        let terms = &self.terms[..self.term_count];

        // Whole words above bit m: v · t^(64i) = v · t^(64i − m) · (1 + t^k [+ t^j + t^l]).
        for i in (top + 1..2 * self.words).rev() {
            let v = c[i];
            if v == 0 {
                continue;
            }
            c[i] = 0;
            let base_bit = WORD_BITS * i - m;
            for &exponent in terms {
                xor_at(c, v, base_bit + exponent);
            }
        }

        // The upper part of the word that holds bit m.
        let rest = c[top] >> shift;
        c[top] &= (1u64 << shift).wrapping_sub(1);
        if rest != 0 {
            for &exponent in terms {
                xor_at(c, rest, exponent);
            }
        }

        let mut result: Words = [0; MAX_WORDS];
        result[..self.words].copy_from_slice(&c[..self.words]);
        result
    }
}

impl PartialEq for PolynomialBasis {
    fn eq(&self, other: &Self) -> bool {
        (self.m, self.k, self.j, self.l) == (other.m, other.k, other.j, other.l)
    }
}

impl Eq for PolynomialBasis {}

pub(crate) fn check_degree(m: u32) -> Result<(), FieldError> {
    if m < MIN_DEGREE {
        return Err(FieldError::DegreeTooSmall(m));
    }
    if m > MAX_DEGREE {
        return Err(FieldError::DegreeTooLarge { m, max: MAX_DEGREE });
    }
    Ok(())
}

pub(crate) fn is_small_prime(n: u32) -> bool {
    n >= 2 && (2..).take_while(|d| d * d <= n).all(|d| n % d != 0)
}

/// c ^= v · t^bit.
fn xor_at(c: &mut [u64; MAX_PRODUCT_WORDS], v: u64, bit: usize) {
    let word = bit / WORD_BITS;
    let shift = bit % WORD_BITS;
    c[word] ^= v << shift;
    if shift != 0 {
        c[word + 1] ^= v >> (WORD_BITS - shift);
    }
}
