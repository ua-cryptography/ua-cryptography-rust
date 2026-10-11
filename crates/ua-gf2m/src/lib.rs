//! Arithmetic of GF(2^m) and binary elliptic curves for DSTU 4145-2002.
//!
//! - [`BinaryField`]: GF(2^m) in a polynomial basis ([`PolynomialBasis`], 5.2) or an optimal normal basis of type 2
//!   ([`OptimalNormalBasis`], В.2), selected by [`FieldBasis`]; shared by its [`FieldElement`]s.
//! - [`FieldElement`]: field arithmetic, trace, half-trace, the standard representation of 5.3.
//! - [`BasisConverter`]: change of basis between PB and ONB of the same field (В.6).
//! - [`BinaryCurve`], [`CurvePoint`]: y² + xy = x³ + Ax² + B, the group law of В.8, the Montgomery ladder, random
//!   points and point compression (6.8–6.10).
//! - [`parse_hex`] and friends: hex text as the standard's tables print it; [`is_probable_prime`]: Miller–Rabin (6.12).
//!
//! Carry-less multiplication uses PMULL (ARMv8) or PCLMULQDQ (x86-64) when the CPU has it, the portable 4-bit window
//! otherwise or with the `portable` feature; `unsafe` code lives in that one module.
//!
//! ```
//! use ua_gf2m::{BinaryField, FieldElement};
//!
//! let field = BinaryField::optimal_normal(173)?;
//! let a = FieldElement::from_hex(&field, "1D26E5282C2647E1B0327CB4F6087932A0A1F006A89F")?;
//! assert_eq!(&a * &a.invert(), field.one());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![deny(unsafe_code)]

mod basis_converter;
mod binary_curve;
mod binary_field;
mod curve_point;
mod errors;
mod field_basis;
mod field_element;
mod gf2_poly;
#[allow(unsafe_code)]
mod hardware_carryless;
mod hex;
mod optimal_normal_basis;
mod polynomial_basis;
mod primality;

pub use basis_converter::BasisConverter;
pub use binary_curve::BinaryCurve;
pub use binary_field::BinaryField;
pub use curve_point::CurvePoint;
pub use field_basis::FieldBasis;
pub use field_element::FieldElement;
pub use optimal_normal_basis::OptimalNormalBasis;
pub use polynomial_basis::PolynomialBasis;

pub use errors::CurveError;
pub use errors::FieldElementError;
pub use errors::FieldError;
pub use errors::HexError;
pub use errors::PointError;

pub use hex::format_hex;
pub use hex::format_hex_padded;
pub use hex::parse_hex;
pub use hex::parse_hex_bytes;
pub use polynomial_basis::MAX_DEGREE;
pub use primality::STANDARD_PRIMALITY_ROUNDS;
pub use primality::integer_sqrt;
pub use primality::is_probable_prime;

/// Whether carry-less multiplication runs on the CPU instruction (PMULL / PCLMULQDQ) rather than the portable path.
pub fn has_hardware_carryless_multiplication() -> bool {
    gf2_poly::uses_hardware()
}
