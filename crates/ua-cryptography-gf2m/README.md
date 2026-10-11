# ua-cryptography-gf2m

Arithmetic of the fields GF(2^m) in the polynomial and the optimal normal basis and of binary elliptic curves over
them, as DSTU 4145-2002 defines them.

## API

```rust
use num_bigint::BigUint;
use rand_core::OsRng;
use ua_cryptography_gf2m::{BasisConverter, BinaryCurve, BinaryField, CurvePoint, FieldElement};

// GF(2^163) with t^163 + t^7 + t^6 + t^3 + 1 (5.2) and GF(2^173) in the optimal normal basis (В.2).
let pb = BinaryField::polynomial(163, 3, 6, 7)?;
let onb = BinaryField::optimal_normal(173)?;

// Elements are read and written in the standard representation of 5.3: an integer, big-endian bytes or hex.
let a = FieldElement::from_hex(&onb, "1D26E5282C2647E1B0327CB4F6087932A0A1F006A89F")?;
assert_eq!(&a * &a.invert(), onb.one());
assert_eq!(a.square().to_biguint(), (a.to_biguint() >> 1u32) | ((a.to_biguint() & BigUint::from(1u32)) << 172u32));

// The curve y² + xy = x³ + Ax² + B and its points; every point is checked to lie on the curve.
let b = ua_cryptography_gf2m::parse_hex("5FF6108462A2DC8210AB403925E638A19C1455D21")?;
let curve = BinaryCurve::from_biguint(&pb, 1, &b)?;
let p = CurvePoint::from_hex(&curve, "72D867F93A93AC27DF9FF01AFFE74885C8C540420", "0224A9C3947852B97C5599D5F4AB81122ADC3FD9B")?;
let q = &p * &BigUint::from(12345u32);                 // the Montgomery ladder
let compressed: Vec<u8> = curve.compress_to_bytes(&q)?; // 6.9
assert_eq!(curve.decompress_from_bytes(&compressed)?, q); // 6.10

// Change of basis (В.6).
let converter = BasisConverter::new(&BinaryField::polynomial(173, 1, 2, 10)?, &onb, &mut OsRng);
assert_eq!(converter.to_normal(&converter.to_polynomial(&a)), a);
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Item | What |
|---|---|
| `BinaryField::polynomial(m, k, j, l) -> Result<BinaryField, FieldError>` | PB t^m + t^k + 1 (`j = l = 0`) or t^m + t^l + t^j + t^k + 1 |
| `BinaryField::optimal_normal(m) -> Result<BinaryField, FieldError>` | ONB of type 2 |
| `BinaryField::m`, `basis() -> &FieldBasis`, `zero`, `one` | degree, parameters, constants; clones share one field |
| `FieldBasis::{Polynomial(PolynomialBasis), OptimalNormal(OptimalNormalBasis)}` | `k()`, `j()`, `l()`, `is_irreducible()`; `STANDARD_DEGREES`, `has_type_two_basis(m)` |
| `FieldElement::from_biguint` / `from_bytes` / `from_hex(field, …) -> Result<_, FieldElementError>` | from the standard representation |
| `FieldElement::random(field, rng)` | 6.4 |
| `&a + &b`, `-`, `*`, `/`; `square`, `square_times(k)`, `invert`, `sqrt`, `trace() -> u8`, `half_trace` | arithmetic (6.5, 6.6, В.4) |
| `to_biguint`, `to_bytes`, `to_hex`, `test_bit(i)`, `is_zero`, `is_one`, `field` | to the standard representation |
| `BinaryCurve::new(field, &a, &b)`, `from_biguint(field, a: u32, &b) -> Result<_, CurveError>` | the curve of 5.4 |
| `BinaryCurve::is_on_curve`, `negate`, `add`, `double`, `multiply`, `multiply_fixed_length`, `multiply_double_and_add` | the group law (В.8) and the López–Dahab Montgomery ladder |
| `BinaryCurve::random_point(rng)`, `compress`, `compress_to_bytes`, `decompress`, `decompress_from_bytes` | 6.8–6.10 |
| `CurvePoint::new(curve, x, y)`, `from_biguint`, `from_hex -> Result<_, PointError>` | a checked point |
| `CurvePoint::x`, `y -> Option<&FieldElement>`, `is_infinity`, `negate`, `twice`, `multiply`; `&p + &q`, `&p - &q`, `-&p`, `&p * &k` | point operations |
| `BasisConverter::new(pb, onb, rng)`, `to_polynomial`, `to_normal`, `convert_curve`, `convert_point`, `find_aligned`, `find_frobenius_shift`, `calculate_normal_polynomial` | В.6 |
| `parse_hex`, `parse_hex_bytes`, `format_hex`, `format_hex_padded` | hex as the standard's tables print it (spaces, '/', "0x" ignored) |
| `is_probable_prime(n, rounds, rng)`, `STANDARD_PRIMALITY_ROUNDS`, `integer_sqrt` | 6.12 |
| `has_hardware_carryless_multiplication()`, `MAX_DEGREE` | the path in use; the largest m (511) |

Refusals are `Result`s (`FieldError`, `FieldElementError`, `CurveError`, `PointError`, `HexError`); mixing elements of
two fields or points of two curves, inverting zero and the half-trace of an even-degree field are programming errors
and panic.

## Design

- A field, and a curve, is an `Arc` shared by its elements and points: equality is by parameters, a clone costs a
  reference count. The basis is a closed set, so it is an enum (`FieldBasis`) rather than a trait.
- Elements are fixed arrays of eight 64-bit words (m ≤ 511 covers every degree of the standard, up to 509): the inner
  loops of multiplication and of the ladder allocate nothing.
- ONB elements are kept in the permuted ("palindromic") form, which makes ONB multiplication two polynomial products
  and a fold (see `OptimalNormalBasis`); the standard form appears only at the boundary.
- Carry-less multiplication uses PMULL (`vmull_p64`, aarch64, feature `aes`) or PCLMULQDQ (x86-64), detected at run
  time, and the portable 4-bit window otherwise or with the `portable` feature. `unsafe` lives in
  `src/hardware_carryless.rs` only (`#![deny(unsafe_code)]` at the root);
  the tests compare both paths word by word and on full fields, on aarch64 and on x86-64.

## Boundaries

- Not constant time: big integers are `num-bigint`; the ladder and the hardware path are regular, but side channels
  were not a goal.
- Point compression (6.9/6.10) recovers x from tr(x) = tr(A), true in the subgroup of odd order; points outside it
  may not round-trip, as in the standard.
- No signature, no named curves: that is `ua-cryptography-dstu4145`.

## Dependencies

`num-bigint`, `num-traits` (the standard representation, scalars), `rand_core` (random elements and points,
Miller–Rabin bases).

## Visibility

Public: the crates.io package `ua-cryptography-gf2m`, published by the author.

## Why not a ready crate

No published crate implements GF(2^m) in an optimal normal basis, and the binary-field crates that exist fix the
field at compile time; DSTU 4145 parameters arrive at run time from certificates in either basis.

## Ported from

`UA.Cryptography.Math` and `UA.Cryptography.EC` of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp).
