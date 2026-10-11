use crate::gf2_poly::{MAX_WORDS, Words};
use crate::{OptimalNormalBasis, PolynomialBasis};

/// The basis of GF(2^m): what defines the field and how its elements are multiplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldBasis {
    /// Polynomial basis given by a primitive trinomial or pentanomial (DSTU 4145-2002, 5.2, table 1).
    Polynomial(PolynomialBasis),
    /// Gaussian optimal normal basis of type 2 (DSTU 4145-2002, В.2, table 2).
    OptimalNormal(OptimalNormalBasis),
}

impl FieldBasis {
    /// Extension degree m.
    pub fn m(&self) -> u32 {
        match self {
            Self::Polynomial(basis) => basis.m(),
            Self::OptimalNormal(basis) => basis.m(),
        }
    }

    /// Number of 64-bit words in the internal representation.
    pub(crate) fn words(&self) -> usize {
        match self {
            Self::Polynomial(basis) => basis.words(),
            Self::OptimalNormal(basis) => basis.words(),
        }
    }

    pub(crate) fn multiply(&self, a: &Words, b: &Words) -> Words {
        match self {
            Self::Polynomial(basis) => basis.multiply(a, b),
            Self::OptimalNormal(basis) => basis.multiply(a, b),
        }
    }

    pub(crate) fn square(&self, a: &Words) -> Words {
        match self {
            Self::Polynomial(basis) => basis.square(a),
            Self::OptimalNormal(basis) => basis.square(a),
        }
    }

    pub(crate) fn one(&self) -> Words {
        match self {
            Self::Polynomial(_) => {
                let mut one: Words = [0; MAX_WORDS];
                one[0] = 1;
                one
            }
            Self::OptimalNormal(basis) => basis.one(),
        }
    }

    /// The standard representation (m-bit integer, little-endian words) → the internal one.
    pub(crate) fn internal_from_standard(&self, standard: &Words) -> Words {
        match self {
            Self::Polynomial(_) => *standard,
            Self::OptimalNormal(basis) => basis.internal_from_standard(standard),
        }
    }

    /// The internal representation → the standard one.
    pub(crate) fn standard_from_internal(&self, internal: &Words) -> Words {
        match self {
            Self::Polynomial(_) => *internal,
            Self::OptimalNormal(basis) => basis.standard_from_internal(internal),
        }
    }
}
