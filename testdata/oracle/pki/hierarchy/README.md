# hierarchy/

The synthetic PKI every C# PKI test is built on (`tests/UA.Cryptography.Tests/Support/Hierarchy.cs`,
`Hierarchy.Shared`), recorded once by `tools/csharp-oracle` (`dotnet run --project tools/csharp-oracle -- pki`).
Keys are generated at random on each run; nothing here names a real person.

```
Test Root CA            root.cer        self-signed, m = 431, DSTU 4145 + DSTU 7564
├── Test Issuing CA     issuing-ca.cer  m = 257
│   ├── Test Signer     signer.cer      m = 257, the key that signs documents
│   └── Test OCSP       ocsp.cer        answers for the Issuing CA's certificates
├── Test TSP Server     tsa.cer         m = 257, time-stamps
└── Test Root OCSP      root-ocsp.cer   answers for the root's certificates
```

| File | What |
|------|------|
| `*.cer` | DER certificates built by `TestPki` (BouncyCastle assembles the ASN.1, the library signs) |
| `keys.json` | per identity: role, certificate file, subject, serial (decimal), validity, signature algorithm, and the key: degree `m`, named-curve index / OID (table Г.1), `d` (big-endian hex), public point `qx`/`qy` (big-endian hex), DKE (hex, GOST 34.311 S-box DKE No. 1); also the signer chain, `validationCertificates` and `allCertificates` (C# `PkiLayer.AllCertificates`: signer first) |
| `ocsp-signer.der` | full OCSPResponse "good" about `signer.cer` from `ocsp.cer` (`IssuingCaOcsp.Respond(Signer, IssuingCa)`) |
| `ocsp-issuing-ca.der` | full OCSPResponse "good" about `issuing-ca.cer` from `root-ocsp.cer` (`RootOcsp.Respond(IssuingCa, Root)`) |
| `signer-twin.cer` | a second certificate for the signer's key with the same subject, issuer and serial number, made by the C# package's `CertificateBuilder` (`CadesSignerTests.ForeignCertificateFailsTheSigningCertificateCheck`) |

The certificates are valid from one day before the run for five years. Signatures in the sibling folders carry a
signing time and a time-stamp, so their validation time is the time they were made, not the time the test runs.

Stands in for `Hierarchy.Shared` in every Rust port of `Pki/**` and `Signatures/**`: `TestPkiTests`
(`HierarchyMirrorsTheNationalChain`, `OcspResponseIsSignedByTheResponderAndGood`), `CertificateTests.SyntheticHierarchyVerifiesWithThePackage`,
`ChainToTrustAnchorTests.SyntheticChainIsRejectedByCzoTrust` / `ChainWithForeignIssuerIsRejected`,
`PathValidationTests` (with `ocsp/`), `JksKeyStoreTests` (keys for the stores the Rust test writes), and the keys a Rust
test needs to issue certificates of its own (impostor roots, a leaf below a leaf) or to run an in-process TSA / OCSP
responder (`tsa` and `ocsp` keys).
