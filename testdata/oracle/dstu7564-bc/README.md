# dstu7564-bc

DSTU 7564:2014 (Kupyna) hashes of BouncyCastle C# 2.7.0 (`Dstu7564Digest`), recorded because Rust has no BouncyCastle
to compare against at run time.

- `dstu7564-bc.json`: an array of `{ bits, message, hash }` (hex) for 256, 384 and 512 bits and random messages of 0,
  1, 51, 52, 53, 63, 64, 65, 115, 116, 117, 127, 128, 129, 1000 and 4097 bytes: around both block sizes (64 and 128
  bytes) and the 12-byte length field. The inputs are drawn as the C# `Dstu7564Tests` draws them.

Produced by `dotnet run --project tools/csharp-oracle -- dstu7564-bc` (`Generators/Dstu7564Bc.cs`).
Read by `crates/ua-cryptography-dstu7564/tests/kupyna.rs`.
