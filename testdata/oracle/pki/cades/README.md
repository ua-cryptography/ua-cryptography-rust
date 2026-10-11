# cades/

CAdES signatures made by the C# test builder `Support/CadesBuilder.cs` (BouncyCastle ASN.1, the library's DSTU 4145)
with the `hierarchy/` signer over `data.txt` (`"test"`), recorded by `tools/csharp-oracle -- pki`. Every file is
listed in `../manifest.json` (format, level, hash, packaging, data, the C# package's verdict and checks, the C#
tests it stands in for) and was verified by the C# package's `SignatureVerifier` before it was kept.

| Files | What |
|-------|------|
| `cades-{dstu7564,gost34311}-{enveloped,detached}-{b,t,x-long}[-content-ts].p7s` | the full grid of `CadesBuilder.Build(data, Hierarchy.Shared, new CadesOptions(hash, enveloped, level, contentTimeStamp))`: hash DSTU 7564-256 or GOST 34.311 (signature DSTU 4145 with the same hash), data inside or detached, level B / T (signatureTimeStampToken) / X-Long (complete certificate and revocation references + values: CA and root certificates, "good" OCSP for signer and CA), with or without a contentTimeStamp signed attribute; signingTime always present |
| `asics-gost34311-t-content-ts.asics` | `CadesBuilder.WrapAsicS("data.txt", data, …)` around the detached GOST T + content time-stamp signature (the exact variant of the C# tests) |
| `asics-dstu7564-x-long.asics` | the same around the detached DSTU 7564 X-Long signature |
| `data.txt` | the signed data |

Verification used for the verdict: trust anchor `hierarchy/root.cer`, extra certificates = every hierarchy
certificate (`PkiLayer.AllCertificates`), offline. Levels below X-Long report the revocation of the signer as a
warning (no OCSP data); the verdict is still valid.

Stands in for: `Pki/Cades/CadesSignerTests.TestBuilderSignatureVerifiesByThePackage` (its five rows are among the
files), `Signatures/CadesTests` (all tests: the BouncyCastle recipe becomes a Rust recipe over these files),
`Pki/Asic/AsicContainerTests.TestBuilderContainersVerify` (ASiC-S half). Tampering (data, signature value, foreign
certificate) is done by the Rust tests on these files; the twin-certificate case is in `package/`.
