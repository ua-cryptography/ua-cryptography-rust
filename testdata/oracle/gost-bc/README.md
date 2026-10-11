# gost-bc

GOST 28147-89 and GOST 34.311-95 answers of BouncyCastle C# 2.7.0 (`Gost28147Engine`, `Gost3411Digest`), recorded
because Rust has no BouncyCastle to compare against at run time.

- `gost-bc.json`: `bouncyCastleSboxes` — the BouncyCastle tables "D-Test" and "D-A" (128 entries, hex);
  `sboxes` — for each of the four tables of the C# `GostTests` (DKE No. 1, the UCC DKE, the CZO 2005 DKE, CryptoPro
  D-A, expanded to 128 entries): 50 random key/plaintext/ciphertext triples and the hashes of random messages of
  0, 1, 31, 32, 33, 63, 64, 65, 100 and 1000 bytes. The inputs are drawn as the C# tests draw them.

Produced by `dotnet run --project tools/csharp-oracle -- gost-bc` (`Generators/GostBc.cs`).
Read by `crates/ua-gost/tests/gost.rs`.
