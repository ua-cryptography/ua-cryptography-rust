# certificates/

What BouncyCastle 2.7.0 reads from certificates, recorded by `tools/csharp-oracle -- pki`, so the Rust X.509 parser
can be compared field by field without BouncyCastle.

| File | What | C# test |
|------|------|---------|
| `real.json` | every real certificate under `testdata/certificates/**` (`*.cer`, `*.crt`; the same files as the C# `TestData/certificates`), keyed by path: version, serial (decimal), subject and issuer DER, validity, signature algorithm, DER TBSCertificate, signature BIT STRING content, SubjectPublicKeyInfo DER, number of extensions, `isCa` (basicConstraints), and the key as `UaPki.ReadPublicKey` reads it (m, n, Q, DKE) | `Pki/X509/CertificateTests.RealCertificateParsesLikeBouncyCastle` (also the BouncyCastle side of `CzoTrustAnchorTests`, `ChainToTrustAnchorTests`, `HistoricalCertificateTests`) |
| `distinguished-names.json` | `new X509Name(text).GetDerEncoded()` for the ASCII DN of the test and for the C# package's `ToString()` of the Cyrillic DN | `Pki/X509/CertificateTests.DistinguishedNameEncodesLikeBouncyCastle` |
| `package-issued.json`, `package-issued/*.cer` | certificates the C# package's `CertificateBuilder` issues (root with basicConstraints, keyUsage, SKI; leaf with AKI, AIA, time-stamping URL) for (DSTU 7564, 257), (GOST 34.311, 431), (DSTU 7564, 163), and how BouncyCastle reads them (sigAlg, basicConstraints, keyUsage bits, extensions, Q, self-signature) | `Pki/X509/CertificateTests.IssuedCertificatesAreAcceptedByBouncyCastleAndUaPki` (the Rust test issues its own certificates and checks them with Rust recipes; these files show what the reference builder makes and BouncyCastle accepts) |
