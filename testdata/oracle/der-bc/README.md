# der-bc

BouncyCastle C# 2.7.0's DER encodings for the cases of the C# `DerTests`, and the C# reader's answers for UTCTime /
GeneralizedTime texts.

Produced by `dotnet run --project tools/csharp-oracle -- der-bc` (`tools/csharp-oracle/Generators/DerBc.cs`) into
`der-bc.json`:

- `integers`, `objectIdentifiers`: the value and BouncyCastle's DER.
- `octetStringHeaders`: for each length, the identifier and length octets BouncyCastle writes (the contents follow
  verbatim; the generator checks that).
- `setsOf`: 50 rounds of OCTET STRING encodings (drawn as the C# test draws them) and BouncyCastle's DER SET.
- `keyUsages`: BouncyCastle's `KeyUsage` encodings.
- `times`: BouncyCastle's UTCTime (2049 pivot) and GeneralizedTime of 2026-10-10T12:34:56Z.
- `berSequence`: BouncyCastle's indefinite-length SEQUENCE holding a constructed OCTET STRING and INTEGER 5.
- `readerTimes`: time texts and the UTC instant the C# `Asn1Node.GetTime` reads (null where it refuses).

Read by `crates/ua-der/tests/der_against_bouncy_castle.rs` and `crates/ua-der/tests/reader_and_writer.rs`.
