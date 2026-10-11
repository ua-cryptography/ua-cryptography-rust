use std::fmt;
use std::sync::{Arc, OnceLock};

use crate::gf2_poly::{self, MAX_WORDS, Words};
use crate::{FieldBasis, FieldElement, FieldError, OptimalNormalBasis, PolynomialBasis};

/// The finite field GF(2^m), shared by its elements: cloning is cheap and clones are the same field.
///
/// Every element has a standard representation, the m-bit string of DSTU 4145-2002, 5.3, and an internal one. For
/// the polynomial basis they coincide; the optimal normal basis keeps a permuted form that turns multiplication into
/// polynomial multiplication. The conversion happens only at the boundary ([`FieldElement::from_biguint`],
/// [`FieldElement::to_biguint`]). Two fields are equal when they have the same degree and the same basis.
#[derive(Clone)]
pub struct BinaryField {
    shape: Arc<FieldShape>,
}

struct FieldShape {
    basis: FieldBasis,
    one: Words,
    /// The trace as a mask: tr(a) = parity(a AND mask), built once from the definition (6.5).
    trace_mask: OnceLock<Words>,
}

impl BinaryField {
    /// GF(2^m) in the polynomial basis t^m + t^k + 1 (`j = l = 0`) or t^m + t^l + t^j + t^k + 1 (DSTU 4145-2002, 5.2).
    pub fn polynomial(m: u32, k: u32, j: u32, l: u32) -> Result<Self, FieldError> {
        let basis = PolynomialBasis::new(m, k, j, l)?;
        Ok(field_of_basis(FieldBasis::Polynomial(basis)))
    }

    /// GF(2^m) in the optimal normal basis of type 2 (DSTU 4145-2002, В.2).
    pub fn optimal_normal(m: u32) -> Result<Self, FieldError> {
        let basis = OptimalNormalBasis::new(m)?;
        Ok(field_of_basis(FieldBasis::OptimalNormal(basis)))
    }

    /// Extension degree m.
    pub fn m(&self) -> u32 {
        self.shape.basis.m()
    }

    /// The basis and its parameters.
    pub fn basis(&self) -> &FieldBasis {
        &self.shape.basis
    }

    /// The zero element.
    pub fn zero(&self) -> FieldElement {
        FieldElement::from_words(self, [0; MAX_WORDS])
    }

    /// The unit (all ones in the optimal normal basis, 5.3).
    pub fn one(&self) -> FieldElement {
        FieldElement::from_words(self, self.shape.one)
    }

    /// Whether both handles are the same field object (a fast path of equality).
    pub(crate) fn is_same_object(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shape, &other.shape)
    }

    /// Number of 64-bit words in the internal representation.
    pub(crate) fn words(&self) -> usize {
        self.shape.basis.words()
    }

    /// Number of 64-bit words of the standard representation.
    pub(crate) fn standard_words(&self) -> usize {
        (self.m() as usize).div_ceil(gf2_poly::WORD_BITS)
    }

    pub(crate) fn one_words(&self) -> &Words {
        &self.shape.one
    }

    pub(crate) fn internal_from_standard(&self, standard: &Words) -> Words {
        self.shape.basis.internal_from_standard(standard)
    }

    pub(crate) fn standard_from_internal(&self, internal: &Words) -> Words {
        self.shape.basis.standard_from_internal(internal)
    }

    pub(crate) fn multiply(&self, a: &Words, b: &Words) -> Words {
        self.shape.basis.multiply(a, b)
    }

    pub(crate) fn square(&self, a: &Words) -> Words {
        self.shape.basis.square(a)
    }

    /// a^(2^k).
    pub(crate) fn square_times(&self, a: &Words, k: u32) -> Words {
        let mut r = *a;
        for _ in 0..k {
            r = self.square(&r);
        }
        r
    }

    /// a⁻¹ = a^(2^m − 2) by Itoh–Tsujii (DSTU 4145-2002, В.4): about log2(m) multiplications and m squarings.
    /// The inverse of zero comes out as zero.
    pub(crate) fn invert(&self, a: &Words) -> Words {
        let n = self.m() - 1; // its binary expansion drives the chain
        let top = u32::BITS - 1 - n.leading_zeros();
        let mut b = *a; // b = a^(2^k − 1), k = 1
        let mut k = 1;
        for i in (0..top).rev() {
            let c = self.square_times(&b, k); // b^(2^k)
            b = self.multiply(&b, &c); // a^(2^(2k) − 1)
            k *= 2;
            if (n >> i) & 1 != 0 {
                b = self.square(&b);
                b = self.multiply(&b, a); // a^(2^(k+1) − 1)
                k += 1;
            }
        }
        self.square(&b)
    }

    /// √a = a^(2^(m−1)).
    pub(crate) fn sqrt(&self, a: &Words) -> Words {
        self.square_times(a, self.m() - 1)
    }

    /// The trace tr(a) (DSTU 4145-2002, 6.5), 0 or 1; GF(2)-linear, so a parity of masked bits.
    pub(crate) fn trace(&self, a: &Words) -> u8 {
        match &self.shape.basis {
            // The trace of every normal basis element is 1.
            FieldBasis::OptimalNormal(_) => gf2_poly::parity(&a[..self.words()]),
            FieldBasis::Polynomial(_) => {
                let mask = self.shape.trace_mask.get_or_init(|| self.calculate_trace_mask());
                let masked: Words = std::array::from_fn(|i| a[i] & mask[i]);
                gf2_poly::parity(&masked)
            }
        }
    }

    /// The trace by the algorithm of 6.5, literally.
    ///
    /// # Panics
    ///
    /// When the result is neither 0 nor 1: the field arithmetic is broken.
    pub(crate) fn trace_by_definition(&self, a: &Words) -> u8 {
        let mut t = *a;
        for _ in 1..self.m() {
            t = self.square(&t);
            t = add_words(&t, a);
        }
        if gf2_poly::is_zero(&t) {
            return 0;
        }
        assert!(
            t == self.shape.one,
            "the trace is neither 0 nor 1: the field arithmetic is broken"
        );
        1
    }

    /// The half-trace htr(a) = Σ a^(4^i), i = 0..(m−1)/2 (DSTU 4145-2002, 6.6).
    ///
    /// # Panics
    ///
    /// When m is even: the half-trace is defined for odd m only.
    pub(crate) fn half_trace(&self, a: &Words) -> Words {
        let m = self.m();
        assert!(m % 2 == 1, "the half-trace is defined for odd m only");
        let mut r = *a;
        for _ in 1..=(m - 1) / 2 {
            r = self.square(&r);
            r = self.square(&r);
            r = add_words(&r, a);
        }
        r
    }

    /// Solves z² + uz = w (DSTU 4145-2002, 6.7): the number of solutions (0, 1 or 2) and one of them.
    pub(crate) fn solve_quadratic(&self, u: &Words, w: &Words) -> (usize, Words) {
        if gf2_poly::is_zero(u) {
            return (1, self.sqrt(w));
        }
        if gf2_poly::is_zero(w) {
            return (2, [0; MAX_WORDS]);
        }

        let u_inverse = self.invert(u);
        let v = self.multiply(w, &self.square(&u_inverse)); // v = w u⁻²
        if self.trace(&v) == 1 {
            return (0, [0; MAX_WORDS]);
        }
        (2, self.multiply(&self.half_trace(&v), u))
    }

    fn calculate_trace_mask(&self) -> Words {
        let mut mask: Words = [0; MAX_WORDS];
        for bit in 0..self.m() as usize {
            let mut element: Words = [0; MAX_WORDS];
            gf2_poly::flip_bit(&mut element, bit);
            if self.trace_by_definition(&element) == 1 {
                gf2_poly::flip_bit(&mut mask, bit);
            }
        }
        mask
    }
}

impl PartialEq for BinaryField {
    fn eq(&self, other: &Self) -> bool {
        self.is_same_object(other) || self.shape.basis == other.shape.basis
    }
}

impl Eq for BinaryField {}

impl fmt::Display for BinaryField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.m();
        match &self.shape.basis {
            FieldBasis::Polynomial(basis) if basis.is_trinomial() => {
                write!(f, "GF(2^{m}), polynomial basis t^{m} + t^{} + 1", basis.k())
            }
            FieldBasis::Polynomial(basis) => write!(
                f,
                "GF(2^{m}), polynomial basis t^{m} + t^{} + t^{} + t^{} + 1",
                basis.l(),
                basis.j(),
                basis.k()
            ),
            FieldBasis::OptimalNormal(_) => write!(f, "GF(2^{m}), optimal normal basis (type 2)"),
        }
    }
}

impl fmt::Debug for BinaryField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BinaryField({self})")
    }
}

/// The field over a checked basis.
fn field_of_basis(basis: FieldBasis) -> BinaryField {
    let one = basis.one();
    BinaryField {
        shape: Arc::new(FieldShape {
            basis,
            one,
            trace_mask: OnceLock::new(),
        }),
    }
}

/// a + b.
pub(crate) fn add_words(a: &Words, b: &Words) -> Words {
    std::array::from_fn(|i| a[i] ^ b[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table 1 of DSTU 4145-2002: m, k, j, l (j = l = 0 for a trinomial).
    #[rustfmt::skip]
    const TABLE_1: [(u32, u32, u32, u32); 60] = [
        (163, 3, 6, 7), (167, 6, 0, 0), (173, 1, 2, 10), (179, 1, 2, 4), (181, 1, 6, 7), (191, 9, 0, 0),
        (193, 15, 0, 0), (197, 1, 2, 21), (199, 1, 2, 11), (211, 1, 6, 12), (223, 1, 2, 12), (227, 1, 2, 21),
        (229, 1, 2, 21), (233, 1, 4, 9), (239, 1, 2, 15), (241, 1, 4, 15), (251, 1, 4, 14), (257, 12, 0, 0),
        (263, 1, 2, 27), (269, 1, 6, 7), (271, 1, 3, 16), (277, 2, 3, 23), (281, 1, 4, 9), (283, 1, 9, 26),
        (293, 1, 6, 11), (307, 2, 4, 8), (311, 1, 4, 29), (313, 1, 3, 7), (317, 2, 5, 9), (331, 2, 5, 12),
        (337, 1, 6, 10), (347, 1, 6, 17), (349, 2, 5, 6), (353, 3, 7, 26), (359, 2, 4, 18), (367, 21, 0, 0),
        (373, 1, 6, 9), (379, 1, 6, 17), (383, 1, 5, 9), (389, 1, 10, 17), (397, 1, 3, 22), (401, 1, 4, 29),
        (409, 1, 6, 15), (419, 1, 14, 21), (421, 1, 4, 7), (431, 1, 3, 5), (433, 1, 5, 15), (439, 2, 3, 8),
        (443, 1, 3, 28), (449, 3, 5, 25), (457, 16, 0, 0), (461, 1, 4, 23), (463, 1, 3, 24), (467, 1, 3, 28),
        (479, 1, 6, 25), (487, 1, 2, 15), (491, 2, 6, 17), (499, 2, 6, 29), (503, 3, 0, 0), (509, 2, 3, 23),
    ];

    fn every_standard_field() -> Vec<BinaryField> {
        let polynomial = TABLE_1
            .iter()
            .map(|&(m, k, j, l)| BinaryField::polynomial(m, k, j, l).unwrap());
        let normal = OptimalNormalBasis::STANDARD_DEGREES
            .iter()
            .map(|&m| BinaryField::optimal_normal(m).unwrap());
        polynomial.chain(normal).collect()
    }

    /// A deterministic element: SplitMix64 words cut to m bits.
    fn element(field: &BinaryField, seed: u64) -> Words {
        let mut state = seed;
        let mut standard: Words = std::array::from_fn(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let z = (state ^ (state >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            let z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        });
        gf2_poly::clear_above(&mut standard, field.m() as usize);
        field.internal_from_standard(&standard)
    }

    #[test]
    fn the_trace_by_mask_equals_the_trace_by_definition_in_every_standard_field() {
        for field in every_standard_field() {
            for seed in 0..4 {
                let a = element(&field, u64::from(field.m()) * 10 + seed);
                assert_eq!(field.trace_by_definition(&a), field.trace(&a), "{field}");
            }
        }
    }

    #[test]
    fn quadratic_equations_are_solved_or_reported_unsolvable() {
        let fields = [
            BinaryField::polynomial(163, 3, 6, 7).unwrap(),
            BinaryField::optimal_normal(173).unwrap(),
        ];
        for field in fields {
            let mut solved = 0;
            for seed in 0..20 {
                let u = element(&field, 2 * seed);
                let w = element(&field, 2 * seed + 1);
                let (count, z) = field.solve_quadratic(&u, &w);
                if count == 0 {
                    continue;
                }
                solved += 1;
                assert_eq!(w, add_words(&field.square(&z), &field.multiply(&u, &z)), "{field}");
            }
            assert!(solved > 3, "{field}: only {solved} of 20 equations were solvable");

            // u = 0: z = √w, the only solution.
            let w = element(&field, 99);
            let (count, z) = field.solve_quadratic(&[0; MAX_WORDS], &w);
            assert_eq!(1, count);
            assert_eq!(w, field.square(&z));
        }
    }

    #[test]
    fn portable_and_hardware_multiplication_agree_in_full_fields() {
        let fields = [
            BinaryField::polynomial(431, 1, 3, 5).unwrap(),
            BinaryField::optimal_normal(431).unwrap(),
        ];
        for field in &fields {
            let inputs: Vec<(Words, Words)> = (0..10)
                .map(|seed| (element(field, 2 * seed), element(field, 2 * seed + 1)))
                .collect();
            let products = || -> Vec<Words> { inputs.iter().map(|(a, b)| field.multiply(a, b)).collect() };
            let expected = products();
            let portable = gf2_poly::with_portable_multiplication(products);
            assert_eq!(expected, portable, "{field}");
        }
    }
}
