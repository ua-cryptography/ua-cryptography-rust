# providers/

The two provider formats of docs/provider-formats.md (C# repository), recorded by `tools/csharp-oracle -- pki` with
the `hierarchy/` PKI. "As the provider makes it" comes from `Support/ProviderProfiles.cs` (BouncyCastle CMS /
System.Xml); "by ua-sign" is the output of the C# command-line tool (`UaSign.Run sign …`) with a JKS key and
`LocalPkiServer` as TSA / OCSP. Every signature was checked against the provider's profile
(`PrivatBankSig.AssertProfile`, `DiiaAsicE.AssertProfile`) and verified by the C# package; the verifications and
verdicts are in `../manifest.json`. Paths, URLs and passwords are in `providers.json`.

| File | What |
|------|------|
| `doc.txt` | the signed document, `"Документ для підпису\n"` |
| `privatbank/customer.cer` | "Test Bank Customer": the signer's key re-certified by the issuing CA with authorityInfoAccess OCSP `http://127.0.0.1:18089/ocsp` and caIssuers `http://127.0.0.1:18089/ca.p7b` (fixed addresses: a Rust test either serves them on that port or answers through injected services) |
| `privatbank/agreement.cer` | the customer's key-agreement certificate (m = 431), as the bank puts it into the key store |
| `privatbank/ca.p7b` | the caIssuers bundle `LocalPkiServer` serves: certs-only CMS with issuing CA, TSA and OCSP responder |
| `privatbank/customer-ocsp.der` | "good" OCSP about the customer from `hierarchy/ocsp.cer` (what LocalPkiServer answers) |
| `privatbank/doc.txt.sig` | `PrivatBankSig.Build`: enveloped CAdES-T, DSTU 7564; signingTime (UTCTime), signingCertificateV2 with issuerSerial; the signature time-stamp without the TSA certificate; only the customer certificate inside |
| `privatbank/key.jks` | the key store as the bank issues it (alias `pb_sign`, chain root, CA, customer, agreement; password `provider formats`), written by the C# package |
| `privatbank/doc.txt.ua-sign.sig` | `ua-sign sign --format cades --level T` with that key store |
| `diia/doc.txt.asice` | `DiiaAsicE.Build`: ASiC-E with XAdES-B-LT as "Дія" makes it (ids `id-…`, `xades-id-…`, `TS-…`, empty Type on the data reference, namespaces declared on the root, CertificateValues CA + root + OCSP responder, one OCSP response about the signer with a zero issuerKeyHash) |
| `diia/key.jks` | the hierarchy signer with its chain (alias `signer`, password `provider formats`), written by the C# package |
| `diia/doc.txt.ua-sign.asice` | `ua-sign sign --format asic-e --level LT` with that key store |

The manifest's verifications mirror the C# test: the bank's `.sig` is valid offline with no options (time-stamp
service certificate: warning), invalid with only the root (`signer: trust` fails: the CA is missing), valid
"online" — `downloads` maps the caIssuers URL to the bundle's certificates and `onlineOcsp` maps certificates to
recorded responses — and valid with the root plus the CA and TSA certificates.

Stands in for `Signatures/ProviderFormatTests` (all four tests; the Rust CLI tests run their own ua-sign and check
its output against the profiles with Rust recipes, and verify these files to cover the providers' own output).
