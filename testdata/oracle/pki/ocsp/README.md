# ocsp/

OCSP responses of the hierarchy's responders (`Support/OcspResponder.cs`: BouncyCastle ASN.1, DSTU 4145 +
DSTU 7564 over the DER tbsResponseData, signature BIT STRING wrapping an OCTET STRING with D, DSTU 7564 CertID, the
responder's certificate inside), recorded by `tools/csharp-oracle -- pki`. All files are full `OCSPResponse`s.
The two plain "good" responses live in `hierarchy/` (`ocsp-signer.der`, `ocsp-issuing-ca.der`).

`ocsp.json` lists every response (including the two in `hierarchy/`) with what BouncyCastle reads from it (responder
name DER, producedAt, the DER tbsResponseData, CertID fields, status tag, thisUpdate) and, for responses about the
signer, the status of the check `path: revocation of 'Test Signer'` when the signer's path (`[issuing-ca]`, anchor
`root`) is validated with only that response.

| File | What | C# test |
|------|------|---------|
| `signer-zero-key-hash.der` | about the signer from its issuer's responder, CertID issuerKeyHash all zeros ("Дія") → Passed | `PathValidationTests.OcspWithAZeroIssuerKeyHashIsMatchedByNameAndSerial` |
| `signer-by-root-responder.der` | about the signer from the root's responder (not authorized by the issuing CA) → Failed | `PathValidationTests.OcspFromAnUnauthorizedResponderIsRejected` |
| `signer-by-root-responder-zero-key-hash.der` | the same with a zero issuerKeyHash → Failed | `PathValidationTests.OcspWithAZeroIssuerKeyHashIsMatchedByNameAndSerial` |
| `request-*.der` | `OCSPRequest` made by the C# package (`OcspResponse.CreateRequest(signer, issuing CA, hash, nonce)`) and BouncyCastle's reading of it (`OcspReq`: CertID, nonce extension) in `ocsp.json` | `HttpServicesTests.OcspServiceAnswersAboutTheCertificate` |

Also read by the Rust ports of `TestPkiTests.OcspResponseIsSignedByTheResponderAndGood` and
`PathValidationTests.SyntheticSignerWithOcspIsFullyValidated` (with the `hierarchy/` responses).
