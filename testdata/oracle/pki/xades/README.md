# xades/

XAdES signatures made by the C# test builder `Support/XadesBuilder.cs` (System.Xml + Microsoft's exclusive C14N, the
library's hashes and DSTU 4145) with the `hierarchy/` signer over `data.txt` (`"test"`, reference URI `data.txt`),
recorded by `tools/csharp-oracle -- pki`. Every signature file is listed in `../manifest.json` and was verified by
the C# package's `SignatureVerifier` before it was kept.

| Files | What |
|-------|------|
| `xades-{dstu7564,gost34311}-{b,t,lt}.xml` | `XadesBuilder.Build(data, "data.txt", Hierarchy.Shared, hash, level).OuterXml` as UTF-8 (no XML declaration), a detached signature next to `data.txt`; level B (signed properties), T (+ SignatureTimeStamp over the canonical ds:SignatureValue), LT (+ CertificateValues: every hierarchy certificate except the signer's, + RevocationValues: "good" OCSP for signer and CA) |
| `asice-{dstu7564,gost34311}-{b,t,lt}.asice` | `XadesBuilder.WrapAsicE("data.txt", data, signature)`: mimetype, data.txt, META-INF/manifest.xml, META-INF/signatures001.xml |
| `c14n-xades-dstu7564-lt.json` | for `xades-dstu7564-lt.xml`: Microsoft's exclusive C14N of every element in document order (`XadesBuilder.Canonicalize`) and its inclusive C14N of the whole document |
| `data.txt` | the signed data |

Verification used for the verdict: trust anchor `hierarchy/root.cer`, extra certificates = every hierarchy
certificate, offline; the detached data is resolved by the reference URI `data.txt`.

Stands in for: `Pki/Xades/XadesSignerTests.TestBuilderSignatureVerifiesByThePackage` (its three rows),
`Signatures/XadesTests` (all tests, both packagings), `Pki/Asic/AsicContainerTests.TestBuilderContainersVerify`
(ASiC-E half), `Pki/Xml/XmlCanonicalizerTests.XadesBuilderDocumentMatchesMicrosoft` (the JSON).
