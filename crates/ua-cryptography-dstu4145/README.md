# ua-cryptography-dstu4145

DSTU 4145-2002, the Ukrainian elliptic-curve digital signature over GF(2^m) in the polynomial and the optimal normal
basis, with the recommended curves of Appendix Г and the random bit generator of Appendix А.

## API

```rust
use ua_cryptography_dstu4145::{DomainParameters, Signer, get_polynomial_curve};

let parameters = get_polynomial_curve(257)?;           // or get_optimal_normal_curve(173)?
let mut signer = Signer::new(&parameters);              // randomness from the OS; Signer::with_rng for another one

let key = signer.generate_key_pair();                   // d and Q = −dP (section 9)
let message = b"Hello";
let signature = signer.sign_message(&key.private_key, message)?; // GOST 34.311 + section 12, D = S‖R (5.10)
assert!(signer.verify_message(&key.public_key, message, &signature)); // section 13

// Another hash: pass H(T) most significant byte first (Appendix Б); the Ukrainian PKI reverses both the hash and D.
let hash = [0x5A; 32];
let d = signer.sign_hash(&key.private_key, &hash)?;
assert!(signer.verify_hash(&key.public_key, &hash, &d));

// Parameters from a certificate: the field, the curve, the compressed base point (6.10), then the checks of section 8.
let field = ua_cryptography_gf2m::BinaryField::polynomial(163, 3, 6, 7)?;
let b = ua_cryptography_gf2m::parse_hex("5FF6108462A2DC8210AB403925E638A19C1455D21")?;
let curve = ua_cryptography_gf2m::BinaryCurve::from_biguint(&field, 1, &b)?;
let compressed_base_point = ua_cryptography_gf2m::parse_hex_bytes("02E2F85F5DD74CE983A5C4237229DAF8A3F35823BE")?;
let base_point = curve.decompress_from_bytes(&compressed_base_point)?;
let n = ua_cryptography_gf2m::parse_hex("400000000000000000002BEC12BE2262D39BCF14D")?;
let explicit = DomainParameters::new(&curve, &base_point, &n)?;
assert_eq!(explicit.validate(), Ok(()));
assert_eq!(explicit, get_polynomial_curve(163)?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Item | What |
|---|---|
| `get_polynomial_curve(m)`, `get_polynomial_curve_by_index(i)`, `get_optimal_normal_curve(m) -> Result<DomainParameters, NamedCurveError>` | tables Г.1 (index = the named-curve OID suffix 0..9) and Г.2, with base points |
| `get_polynomial_field(m)`, `POLYNOMIAL_TABLE`, `POLYNOMIAL_DEGREES`, `NORMAL_DEGREES` | table 1; the degrees of Г.1 and Г.2 |
| `DomainParameters::new(&curve, &base_point, &n) -> Result<_, DomainParametersError>` | explicit parameters (section 7) |
| `curve`, `field`, `base_point`, `n`, `minimum_signature_bits` | the parts; the shortest L_D (5.7) |
| `validate() -> Result<(), ParameterCheckFailure>`, `validate_public_key(&q) -> Result<(), PublicKeyCheckFailure>` | 8.1–8.3, 10.1; the failure names its clause |
| `generate_base_point(curve, n, rng)`, `check_mov_condition(n, m)`, `generate_integer(rng)` | 7.3, 6.13, 6.3 |
| `Signer::new(&parameters)`, `Signer::with_rng(&parameters, rng)` | the OS generator or any `RngCore + CryptoRng` |
| `generate_key_pair() -> KeyPair`, `calculate_public_key(&d) -> Result<CurvePoint, SigningError>` | section 9 |
| `generate_presignature() -> Presignature`, `calculate_presignature(&e) -> Option<Presignature>` | section 11 |
| `sign_hash(&d, hash)`, `sign_hash_with_length(&d, hash, bits)`, `sign_message(&d, message)`, `sign_message_with_hasher(&d, message, &mut Gost34311) -> Result<Vec<u8>, SigningError>` | section 12, D big-endian |
| `sign(&d, &h, &presignature) -> Result<Option<(r, s)>, SigningError>` | steps 9–13 with a given presignature |
| `verify_hash(&q, hash, signature)`, `verify_message`, `verify_message_with_hasher`, `verify(&q, &h, &r, &s) -> bool` | section 13 |
| `RandomGenerator::new(&key, &seed, date_time, sbox) -> Result<_, RandomGeneratorError>`, `from_os_entropy()`, `next_bit()` | Appendix А; implements `RngCore + CryptoRng` |
| `field_element_to_integer`, `hash_to_field_element`, `encode_signature`, `decode_signature`, `bit_length`, `hash_message`, `hash_message_with_hasher` | 5.1, 5.8–5.11, 6.2 |

## Performance

`cargo run --release -p ua-cryptography-dstu4145 --example bench` (add `--features ua-cryptography-gf2m/portable` for
the portable multiplication). Apple M-series, one core, PMULL; the C# column is the table of the C# README (Apple M2,
.NET 10):

| Curve | multiply, ns | square, ns | invert, µs | kP, µs | sign, µs | verify, µs |
|---|---:|---:|---:|---:|---:|---:|
| PB 163 | 39 (C# 39) | 34 (32) | 8.4 (6.1) | 67 (65) | 70 (67) | 137 (135) |
| PB 257 | 44 (40) | 32 (30) | 10.1 (8.5) | 122 (120) | 123 (122) | 252 (257) |
| PB 431 | 95 (113) | 57 (58) | 26.6 (26.7) | 361 (427) | 365 (431) | 778 (879) |
| ONB 173 | 48 (55) | 22 (31) | 5.3 (6.0) | 74 (85) | 79 (89) | 153 (177) |
| ONB 233 | 68 (91) | 25 (39) | 7.3 (9.7) | 120 (170) | 123 (176) | 245 (349) |
| ONB 431 | 134 (197) | 36 (50) | 18.6 (23.5) | 450 (618) | 441 (625) | 883 (1260) |

The field figures include the reference count of the result's field handle. Without PMULL everything is 2–4 times
slower (PB 431 kP 1067 µs, ONB 431 kP 1836 µs).

## Boundaries

- The hash is GOST 34.311 or any hash the caller computes; DSTU 7564 lives in its own crate.
- No ASN.1, certificates or key containers: that is `ua-cryptography-pki`. The byte order of the Ukrainian PKI (reversed
  hash and D) is the caller's.
- Not constant time (`num-bigint`); the ladder runs a fixed number of steps for secret scalars.
- `validate` takes its Miller–Rabin bases from the OS generator.

## Dependencies

`ua-cryptography-gf2m` (fields, curves), `ua-cryptography-gost` (GOST 34.311, GOST 28147), `num-bigint`, `num-traits`,
`rand_core`; `serde_json` (dev) reads the BouncyCastle answers recorded in `testdata/oracle/dstu4145-bc`.

## Visibility

Public: the crates.io package `ua-cryptography-dstu4145`, published by the author.

## Why not a ready crate

None exists for DSTU 4145 in Rust; BouncyCastle (Java, C#) covers the polynomial basis only.

## Ported from

`UA.Cryptography.Dstu4145` of [ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp).
