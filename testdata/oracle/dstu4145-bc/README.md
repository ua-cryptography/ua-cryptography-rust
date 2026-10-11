# dstu4145-bc

DSTU 4145-2002 in the polynomial basis as BouncyCastle C# 2.7.0 computes it (`DSTU4145NamedCurves`,
`DSTU4145Signer`), recorded because Rust has no BouncyCastle to compare against at run time. All keys are synthetic,
generated on the spot.

- `dstu4145-bc.json`, `curves`: for each of the 10 named curves of BouncyCastle (the OIDs `1.2.804.2.1.1.1.1.3.1.1.2.0`
  … `.9`, table Г.1):
  - `m`, `k1`, `k2`, `k3`, `a`, `b`, `n`, `gx`, `gy` — the curve as BouncyCastle defines it;
  - `multiples` — three `{ k, x, y }` with (x, y) = kG by BouncyCastle, k drawn as the C# test draws it;
  - `bouncyCastleSignatures` — two `{ qx, qy, hash, r, s }`: a BouncyCastle signature of a random hash under a key
    of the C# library (BouncyCastle → ours);
  - `csharpSignatures` — two `{ d, qx, qy, hash, e, r, s, signature }`: a signature of the C# library with the
    presignature e, which BouncyCastle verified while recording (`bouncyCastleVerified`). Rust cannot ask BouncyCastle
    to verify its own signatures, so it must reproduce these bit for bit from (d, hash, e) — ours → BouncyCastle.
  - Hashes are written most significant byte first (Appendix Б); BouncyCastle was given them reversed.
- `randomGenerator`: 64 bytes of the C# Appendix А generator (`Dstu4145RandomGenerator`) for the key 01..20, the seed
  0102030405060708 and D = 0123456789ABCDEF, the state of the C# `RandomGeneratorTests`.

Produced by `dotnet run --project tools/csharp-oracle -- dstu4145-bc` (`Generators/Dstu4145Bc.cs`). Read by
`crates/ua-cryptography-dstu4145/tests/bouncy_castle.rs` and
`crates/ua-cryptography-dstu4145/tests/random_generator.rs`.
