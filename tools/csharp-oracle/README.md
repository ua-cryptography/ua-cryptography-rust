# csharp-oracle

Reference fixtures for the Rust tests, produced by the C# implementation
([ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp)) and the oracles its tests use:
BouncyCastle C# 2.7.0 and `System.Security.Cryptography.Xml`. Rust has no BouncyCastle, so where a C# test compares
against it at run time, the Rust test compares against values recorded here once.

Everything written is synthetic: keys are generated on the spot, certificates name no real person.

```bash
# the C# repository is expected next to this one (../ua-cryptography-csharp)
dotnet run --project tools/csharp-oracle                       # every generator
dotnet run --project tools/csharp-oracle -- dstu4145-bc        # one generator
dotnet run --project tools/csharp-oracle -p:CSharpRepo=/path/to/ua-cryptography-csharp
```

Each generator is one class in `Generators/` implementing `IFixtureGenerator`; it writes `testdata/oracle/<name>/`
and the folder's `README.md` says which Rust tests read it. The test support code of the C# repository
(`tests/UA.Cryptography.Tests/Support`) is compiled in unchanged.
