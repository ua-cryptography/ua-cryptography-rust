use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Add, Div, Mul, Sub};

use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use crate::binary_field::add_words;
use crate::gf2_poly::{self, MAX_WORDS, WORD_BITS, Words};
use crate::{BinaryField, FieldElementError, hex};

const BYTE_BITS: usize = 8;
const HEX_DIGIT_BITS: usize = 4;

/// An immutable element of a [`BinaryField`]; arithmetic works on references (`&a * &b`) and values alike.
///
/// # Panics
///
/// The operators panic when the operands belong to different fields, and division and [`invert`] panic for zero.
///
/// [`invert`]: FieldElement::invert
#[derive(Clone)]
pub struct FieldElement {
    field: BinaryField,
    value: Words,
}

impl FieldElement {
    /// The element whose standard representation (DSTU 4145-2002, 5.3) is `value`, an integer of at most m bits.
    pub fn from_biguint(field: &BinaryField, value: &BigUint) -> Result<Self, FieldElementError> {
        if value.bits() > u64::from(field.m()) {
            return Err(FieldElementError::TooWide { m: field.m() });
        }
        Ok(element_of_standard(field, value))
    }

    /// The element whose standard representation is the big-endian integer `bytes`.
    pub fn from_bytes(field: &BinaryField, bytes: &[u8]) -> Result<Self, FieldElementError> {
        Self::from_biguint(field, &BigUint::from_bytes_be(bytes))
    }

    /// The element whose standard representation is the hex `text` (whitespace, '/' and "0x" are ignored).
    pub fn from_hex(field: &BinaryField, text: &str) -> Result<Self, FieldElementError> {
        Self::from_biguint(field, &hex::parse_hex(text)?)
    }

    /// A random element (DSTU 4145-2002, 6.4): the first generated bits become the most significant ones.
    pub fn random(field: &BinaryField, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let m = field.m() as usize;
        let mut bytes = vec![0u8; m.div_ceil(BYTE_BITS)];
        rng.fill_bytes(&mut bytes);
        let value = BigUint::from_bytes_be(&bytes) >> (BYTE_BITS * bytes.len() - m);
        element_of_standard(field, &value)
    }

    /// The field the element belongs to.
    pub fn field(&self) -> &BinaryField {
        &self.field
    }

    /// Whether this is the zero element.
    pub fn is_zero(&self) -> bool {
        gf2_poly::is_zero(&self.value)
    }

    /// Whether this is the unit.
    pub fn is_one(&self) -> bool {
        self.value == *self.field.one_words()
    }

    /// self².
    pub fn square(&self) -> Self {
        self.with_value(self.field.square(&self.value))
    }

    /// self^(2^k).
    pub fn square_times(&self, k: u32) -> Self {
        self.with_value(self.field.square_times(&self.value, k))
    }

    /// self⁻¹ (Itoh–Tsujii, DSTU 4145-2002, В.4).
    ///
    /// # Panics
    ///
    /// For zero, which has no inverse.
    pub fn invert(&self) -> Self {
        assert!(!self.is_zero(), "zero has no inverse in a field");
        self.with_value(self.field.invert(&self.value))
    }

    /// The square root self^(2^(m−1)).
    pub fn sqrt(&self) -> Self {
        self.with_value(self.field.sqrt(&self.value))
    }

    /// The trace (DSTU 4145-2002, 6.5): 0 or 1.
    pub fn trace(&self) -> u8 {
        self.field.trace(&self.value)
    }

    /// The half-trace (DSTU 4145-2002, 6.6).
    ///
    /// # Panics
    ///
    /// When m is even: the half-trace is defined for odd m only.
    pub fn half_trace(&self) -> Self {
        self.with_value(self.field.half_trace(&self.value))
    }

    /// The standard representation (DSTU 4145-2002, 5.3) as an integer.
    pub fn to_biguint(&self) -> BigUint {
        let standard = self.field.standard_from_internal(&self.value);
        let digits: Vec<u32> = standard[..self.field.standard_words()]
            .iter()
            .flat_map(|&word| [word as u32, (word >> (WORD_BITS / 2)) as u32])
            .collect();
        BigUint::new(digits)
    }

    /// The standard representation as big-endian bytes, ⌈m / 8⌉ of them.
    pub fn to_bytes(&self) -> Vec<u8> {
        let length = (self.field.m() as usize).div_ceil(BYTE_BITS);
        let digits = self.to_biguint().to_bytes_be();
        let mut bytes = vec![0u8; length - digits.len()];
        bytes.extend_from_slice(&digits);
        bytes
    }

    /// The standard representation as upper-case hex, padded to the full field width.
    pub fn to_hex(&self) -> String {
        hex::format_hex_padded(&self.to_biguint(), (self.field.m() as usize).div_ceil(HEX_DIGIT_BITS))
    }

    /// Bit i of the standard representation.
    pub fn test_bit(&self, i: u32) -> bool {
        self.to_biguint().bit(u64::from(i))
    }

    pub(crate) fn from_words(field: &BinaryField, value: Words) -> Self {
        Self {
            field: field.clone(),
            value,
        }
    }

    pub(crate) fn words(&self) -> &Words {
        &self.value
    }

    fn with_value(&self, value: Words) -> Self {
        Self {
            field: self.field.clone(),
            value,
        }
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.field == other.field
    }
}

impl Eq for FieldElement {}

impl Hash for FieldElement {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement({} in GF(2^{}))", self.to_hex(), self.field.m())
    }
}

impl Add for &FieldElement {
    type Output = FieldElement;

    fn add(self, other: &FieldElement) -> FieldElement {
        assert_same_field(self, other);
        self.with_value(add_words(&self.value, &other.value))
    }
}

/// Subtraction equals addition in characteristic 2.
impl Sub for &FieldElement {
    type Output = FieldElement;

    #[allow(clippy::suspicious_arithmetic_impl)] // a − b = a + b in characteristic 2
    fn sub(self, other: &FieldElement) -> FieldElement {
        self + other
    }
}

impl Mul for &FieldElement {
    type Output = FieldElement;

    fn mul(self, other: &FieldElement) -> FieldElement {
        assert_same_field(self, other);
        self.with_value(self.field.multiply(&self.value, &other.value))
    }
}

impl Div for &FieldElement {
    type Output = FieldElement;

    #[allow(clippy::suspicious_arithmetic_impl)] // a / b = a · b⁻¹
    fn div(self, other: &FieldElement) -> FieldElement {
        self * &other.invert()
    }
}

macro_rules! forward_owned_operator {
    ($operator:ident, $method:ident) => {
        impl $operator for FieldElement {
            type Output = FieldElement;

            fn $method(self, other: FieldElement) -> FieldElement {
                (&self).$method(&other)
            }
        }

        impl $operator<&FieldElement> for FieldElement {
            type Output = FieldElement;

            fn $method(self, other: &FieldElement) -> FieldElement {
                (&self).$method(other)
            }
        }

        impl $operator<FieldElement> for &FieldElement {
            type Output = FieldElement;

            fn $method(self, other: FieldElement) -> FieldElement {
                self.$method(&other)
            }
        }
    };
}

forward_owned_operator!(Add, add);
forward_owned_operator!(Sub, sub);
forward_owned_operator!(Mul, mul);
forward_owned_operator!(Div, div);

/// # Panics
///
/// When the elements belong to different fields: only buggy code mixes them.
pub(crate) fn assert_same_field(a: &FieldElement, b: &FieldElement) {
    assert!(
        a.field.is_same_object(&b.field) || a.field == b.field,
        "the elements belong to different fields: {} and {}",
        a.field,
        b.field
    );
}

/// The element of a standard representation known to fit into m bits.
fn element_of_standard(field: &BinaryField, value: &BigUint) -> FieldElement {
    let mut standard: Words = [0; MAX_WORDS];
    for (word, digit) in standard.iter_mut().zip(value.iter_u64_digits()) {
        *word = digit;
    }
    FieldElement::from_words(field, field.internal_from_standard(&standard))
}
