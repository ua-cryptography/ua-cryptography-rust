# tsp/

RFC 3161 time-stamp tokens of the hierarchy's TSA (`Support/TimeStampAuthority.cs`, BouncyCastle ASN.1, signed by
the library: DSTU 4145 with the requested hash, signingCertificateV2), recorded by `tools/csharp-oracle -- pki`.
`tsp.json` lists each file with what BouncyCastle reads from it.

| File | What | C# test |
|------|------|---------|
| `covered.bin` | `"covered bytes"`, the data the tokens cover | |
| `token-dstu7564.der`, `token-gost34311.der` | `Tsa.Stamp(covered, hash)`, TSA certificate inside; policies …2.3.4.1.1 / …2.3.1 | `TimeStampTokenTests.TokenCoversItsDataOnly` (both rows), `TestPkiTests.TimeStampTokenCoversDataAndIsSignedByTheTsa` (both rows; C# stamps 100 random bytes) |
| `token-*-no-certificate.der` | the same without the TSA certificate: found among known certificates by issuer and serial only | `TimeStampTokenTests.ServiceCertificateIsFoundAmongKnownOnesWhenNotEmbedded`, `TestPkiTests.TimeStampSignerIsFoundByIssuerAndSerialWhenNotEmbedded` (C# stamps `[1, 2, 3]`) |
| `data.bin`, `token-dstu7564-over-data.der` | a genuine token over `"data"`, to put into a CAdES signature over `"data"` as its signature time-stamp (imprint fails) | `TimeStampTokenTests.SignatureTimeStampOverOtherBytesFailsTheSignature` |
| `response-granted.der` | `TimeStampResp { granted, token }` as `LocalPkiServer` answers: token over 32 zero bytes (DSTU 7564) with the nonce in `tsp.json` | `HttpServicesTests.ForgedTimeStampResponsesAreRejected` |
| `response-rejection.der` | `TimeStampResp { rejection }` without a token | `HttpServicesTests.ForgedTimeStampResponsesAreRejected` |
| `request-*.der` | `TimeStampReq` made by the C# package (`TimeStampProtocol.CreateRequest`) and BouncyCastle's reading of it (`TimeStampRequest`) in `tsp.json` | `HttpServicesTests.TimeStampServiceAnswersTheRequest` (LocalPkiServer parses the request with BouncyCastle) |

A Rust test that needs a token over bytes it makes at run time (a signature value) signs one itself with the TSA key
in `hierarchy/keys.json`; the CAdES/XAdES fixtures carry tokens over their own signature values.
