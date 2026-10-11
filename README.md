# ua-cryptography (Rust)

Ukrainian cryptographic standards and the signature formats of the Ukrainian PKI in Rust — a port of the C# reference
implementation [ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp), checked against it
value by value:

- **DSTU 4145-2002** — elliptic-curve digital signature over GF(2^m) in both bases, **polynomial (PB)** and **optimal
  normal (ONB)**, with all recommended curves and the random bit generator of Appendix А;
- **GOST 34.311-95** (with any S-box table / DKE) and **GOST 28147-89**;
- **DSTU 7564:2014 "Kupyna"** — 256/384/512-bit hash;
- **DSTU 7624:2014 "Kalyna"** — 128/256/512-bit block cipher and the ECB, CBC, CFB, OFB, CTR, CMAC, CCM, GCM, GMAC,
  XTS and KW modes;
- **PKI formats** — DER, X.509 with DSTU 4145 keys, JKS key stores, CMS/CAdES (B, T, X Long), RFC 3161 time-stamps,
  OCSP, inclusive and exclusive XML canonicalization, XAdES (B, T, LT), ASiC-S and ASiC-E, certification path
  validation;
- **ua-sign** — a command-line tool that creates keys in JKS, signs files in all these formats and verifies them
  ([docs/ua-sign.md](docs/ua-sign.md)).

The appendices and clauses of DSTU 4145-2002 are cited by their original Cyrillic designators: Appendix А, Б, В, Г,
clauses Б.1, В.8, tables Г.1, Г.2 and so on. The text of the standard is not included: it is copyrighted by
Derzhstandart of Ukraine and may not be redistributed.

## Quick start

```rust
use ua_dstu4145::{Signer, get_polynomial_curve};

let parameters = get_polynomial_curve(257)?;            // or get_optimal_normal_curve(173)?
let mut signer = Signer::new(&parameters);               // OS randomness; Signer::with_rng for another generator

let key = signer.generate_key_pair();                    // d and Q = −dP (section 9)
let signature = signer.sign_message(&key.private_key, b"Hello")?;  // GOST 34.311 + section 12, D = S‖R (5.10)
assert!(signer.verify_message(&key.public_key, b"Hello", &signature)); // section 13
```

With another hash, pass H(T) most significant byte first (Appendix Б); the Ukrainian PKI reverses the bytes of the hash
and stores D in little-endian ([docs/signature-formats.md](docs/signature-formats.md), section 1):

```rust
let mut h = ua_dstu7564::Kupyna::calculate_hash(b"Hello", ua_dstu7564::HashSize::Bits256);
h.reverse();                                             // as qualified signature tools sign it
let mut d = signer.sign_hash(&key.private_key, &h)?;
d.reverse();                                             // how D is stored in certificates, CMS and XML
```

Authenticated encryption with Kalyna:

```rust
use ua_dstu7624::{BlockSize, Gcm};

let gcm = Gcm::new(BlockSize::Bits256, &key256)?;
let sealed = gcm.encrypt(&nonce, &associated_data, &plain_text, 256)?;
let opened = gcm.decrypt(&nonce, &associated_data, &sealed, 256)?; // Err(CipherFailure::TagMismatch) if forged
```

Signing and verifying files: see the `ua-pki` README, or the command line:

```bash
cargo build --release -p ua-sign
build_scripts/ua-sign.sh keygen --keystore key.jks --subject "CN=Name,O=Organization,C=UA"
build_scripts/ua-sign.sh sign --keystore key.jks --format asic-e --in contract.pdf
build_scripts/ua-sign.sh verify --in contract.pdf.asice --trust key.cer
build_scripts/demo.sh                                    # every format, verified, a tampered copy rejected
```

## Crates

| Crate | What it offers |
|---|---|
| [`ua-gf2m`](crates/ua-gf2m) | GF(2)[x] with hardware carry-less multiplication (PMULL / PCLMULQDQ) and a portable fallback; GF(2^m) in PB and ONB; basis conversion (В.6); binary curves, Montgomery ladder, point compression |
| [`ua-gost`](crates/ua-gost) | GOST 28147-89, GOST 34.311-95 with any DKE |
| [`ua-dstu4145`](crates/ua-dstu4145) | domain parameters and their checks (section 8), the curves of Appendix Г, keys, signing, verification, encodings (5.x), the generator of Appendix А |
| [`ua-dstu-sboxes`](crates/ua-dstu-sboxes) | the S-boxes shared by DSTU 7564 and DSTU 7624 |
| [`ua-dstu7564`](crates/ua-dstu7564) | Kupyna |
| [`ua-dstu7624`](crates/ua-dstu7624) | Kalyna and its modes, one file per mode |
| [`ua-der`](crates/ua-der) | DER/BER reader keeping the exact bytes of every element, DER writer, PEM |
| [`ua-xml-c14n`](crates/ua-xml-c14n) | Canonical XML 1.0 and Exclusive C14N 1.0 over `roxmltree`, safe parsing |
| [`ua-pki`](crates/ua-pki) | X.509, JKS, CMS/CAdES, TSP, OCSP, XAdES, ASiC, certification paths, HTTP clients of the PKI services |
| [`ua-sign`](crates/ua-sign) | the command-line tool |
| [`ua-ffi`](crates/ua-ffi) | `ua_cryptography`, everything above as a native library: a C ABI for Windows, macOS, Linux, Android, iOS and JavaScript bindings for the browser |

Each crate has a README with its API, boundaries and dependencies.

## Build and test

Requires Rust 1.85+ (edition 2024).

```bash
cargo test --workspace                                   # every crate, optimized test profile
cargo clippy --workspace --all-targets                   # zero warnings
cargo run --release -p ua-dstu4145 --example bench       # performance table
cargo run --release -p ua-dstu4145 --example bench --features ua-gf2m/portable  # without PMULL/PCLMUL
build_scripts/interop.sh                                 # cross-verification with the C# ua-sign (needs .NET 10)
build_scripts/ffi-header.sh                              # regenerates the C header of ua-ffi (needs cbindgen)
```

CI (`.github/workflows/ci.yml`) runs the tests on Linux, Windows and macOS on every push and pull request. A `v*` tag
runs `.github/workflows/release.yml`: the tests, then the `ua_cryptography` library for Windows (x64, ARM64), macOS
(universal), Linux (x64, ARM64), Android (four ABIs), iOS (XCFramework) and the browser (WebAssembly), attached to
a GitHub release — see [crates/ua-ffi](crates/ua-ffi).

## How the port is verified

Everything the C# tests check is checked here, test by test (the Rust tests are named after the C# ones). Where a C#
test asks an independent implementation at run time — BouncyCastle C# 2.7.0 for DSTU 4145 (PB), GOST, Kupyna, DER,
X.509, CMS, time-stamps and OCSP; Microsoft's `System.Security.Cryptography.Xml` for C14N — its answers were recorded
once by [`tools/csharp-oracle`](tools/csharp-oracle) into [`testdata/oracle`](testdata/oracle), each folder with a
README naming the tests that read it:

- **Algorithms**: the worked examples of Appendix Б (Б.1, Б.2) value by value; the reference X9.62 ONB
  multiplication; all 15 recommended curves pass the checks of clause 8; BouncyCastle signatures verify and C#
  signatures with a fixed e are reproduced bit for bit; GOST R 34.11-94 vectors and BouncyCastle with four S-box
  tables; the DSTU 7564 examples; the 590 DSTU 7624 vectors of BouncyCastle Java 1.86.
- **Formats**: 66 signatures made by the C# test builders (BouncyCastle-assembled CAdES, XAdES, ASiC at every level,
  the PrivatBank and "Дія" profiles) and by the C# package itself get the same verdict and the same list of checks
  from the Rust verifier as from the C# one; real certificates of the ЦЗО, "Дія" and PrivatBank CAs and five
  historical ones parse as BouncyCastle parses them and their signatures verify; C14N of every element subtree of
  the test documents equals Microsoft's; time-stamp and OCSP requests are byte-identical to the C# ones.
- **Interop**: `build_scripts/interop.sh` signs with each implementation in every format and verifies with the other, and
  each reads the other's key stores.

## Performance

Apple Silicon, one core, PMULL (`cargo run --release -p ua-dstu4145 --example bench`); the C# figures (.NET 10,
Apple M2) in parentheses:

| Curve | multiply, ns | square, ns | invert, µs | kP, µs | sign, µs | verify, µs |
|---|---:|---:|---:|---:|---:|---:|
| PB 163 | 39 (39) | 34 (32) | 8.4 (6.1) | 67 (65) | 70 (67) | 137 (135) |
| PB 257 | 44 (40) | 32 (30) | 10.1 (8.5) | 122 (120) | 123 (122) | 252 (257) |
| PB 431 | 95 (113) | 57 (58) | 26.6 (26.7) | 361 (427) | 365 (431) | 778 (879) |
| ONB 173 | 48 (55) | 22 (31) | 5.3 (6.0) | 74 (85) | 79 (89) | 153 (177) |
| ONB 233 | 68 (91) | 25 (39) | 7.3 (9.7) | 120 (170) | 123 (176) | 245 (349) |
| ONB 431 | 134 (197) | 36 (50) | 18.6 (23.5) | 450 (618) | 441 (625) | 883 (1260) |

Without the hardware instruction everything is 2–4 times slower. How ONB multiplication is reduced to polynomial
multiplication and why the Montgomery ladder is used: [docs/implementation-notes.md](docs/implementation-notes.md)
and the C# README.

## Limitations

- Not audited. Big-integer arithmetic is `num-bigint` (not constant time); the portable carry-less multiplication
  uses a 4-bit window table. The Montgomery ladder and the hardware path are regular, but protection against
  side-channel attacks was not a goal.
- No PAdES, CRLs, archive time-stamps, PKCS#12 or IIT key containers; certificate policies are not evaluated.
- Field degrees up to m = 511 (every degree of the standard's tables fits).

## Documentation

- [docs/signature-formats.md](docs/signature-formats.md) — XAdES, CAdES, PAdES, ASiC, time-stamps and OCSP in the
  Ukrainian PKI, and how to verify them.
- [docs/provider-formats.md](docs/provider-formats.md) — what PrivatBank (CAdES-T `.sig`) and "Дія" (ASiC-E) hand out.
- [docs/ua-sign.md](docs/ua-sign.md) — the command-line tool and its scripts.
- [docs/implementation-notes.md](docs/implementation-notes.md) — errors in the text of the standard, PKI conventions,
  the alternatives, the 2010 project.

These documents come from the C# repository; where they name a C# test or file, the Rust test of the same name (in
snake_case) checks the same thing.

## License

[MIT](LICENSE). The DSTU 7624 code is translated from BouncyCastle Java (MIT); the base points of the recommended
curves were published by the cryptography.org.ua project — see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
