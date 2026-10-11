//! DSTU 4145-2002: the elliptic-curve digital signature over GF(2^m) in the polynomial and the optimal normal basis.
//!
//! - [`DomainParameters`]: the curve, the base point P and its order n (section 7), the checks of section 8 and of
//!   a public key (10.1), random integers (6.3).
//! - [`Signer`]: keys (9), presignatures (11), signing (12) and verification (13) of a hash or of a message hashed
//!   with GOST 34.311; [`KeyPair`] and [`Presignature`] are what it hands out.
//! - [`RandomGenerator`]: the random bit generator of Appendix А on GOST 28147.
//! - [`get_polynomial_curve`], [`get_optimal_normal_curve`]: the recommended curves of Appendix Г (tables Г.1, Г.2)
//!   with base points; [`POLYNOMIAL_TABLE`]: the polynomials of table 1.
//! - [`encode_signature`] and the other conversions of section 5.
//!
//! The field and curve arithmetic is `ua-gf2m`; GOST 28147 and GOST 34.311 are `ua-gost`.
//!
//! ```
//! let parameters = ua_dstu4145::get_polynomial_curve(257)?;
//! let mut signer = ua_dstu4145::Signer::new(&parameters);
//! let key = signer.generate_key_pair();
//! let signature = signer.sign_message(&key.private_key, b"Hello")?;
//! assert!(signer.verify_message(&key.public_key, b"Hello", &signature));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

mod domain_parameters;
mod encoding;
mod errors;
mod key_pair;
mod named_curves;
mod presignature;
mod random_generator;
mod signer;

pub use domain_parameters::DomainParameters;
pub use key_pair::KeyPair;
pub use presignature::Presignature;
pub use random_generator::RandomGenerator;
pub use signer::Signer;

pub use errors::DomainParametersError;
pub use errors::NamedCurveError;
pub use errors::ParameterCheckFailure;
pub use errors::PublicKeyCheckFailure;
pub use errors::RandomGeneratorError;
pub use errors::SignatureEncodingError;
pub use errors::SigningError;

pub use encoding::bit_length;
pub use encoding::decode_signature;
pub use encoding::encode_signature;
pub use encoding::field_element_to_integer;
pub use encoding::hash_message;
pub use encoding::hash_message_with_hasher;
pub use encoding::hash_to_field_element;
pub use named_curves::NORMAL_DEGREES;
pub use named_curves::POLYNOMIAL_DEGREES;
pub use named_curves::POLYNOMIAL_TABLE;
pub use named_curves::get_optimal_normal_curve;
pub use named_curves::get_polynomial_curve;
pub use named_curves::get_polynomial_curve_by_index;
pub use named_curves::get_polynomial_field;
