# ua-cryptography

Ukrainian cryptographic standards and the signature formats of the Ukrainian PKI for JavaScript, in WebAssembly:
DSTU 4145-2002 signatures, DSTU 7564 "Kupyna", DSTU 7624 "Kalyna" with its modes, GOST 28147-89, GOST 34.311-95, JKS
key stores, and CAdES, XAdES, ASiC-S and ASiC-E signing and verification. Built from the Rust crates of
[ua-cryptography-rust](https://github.com/ua-cryptography/ua-cryptography-rust), checked against the C# reference
implementation.

```bash
npm install ua-cryptography
```

## Usage

Node.js 20.19+ loads the WebAssembly at import:

```js
import { dstu7564CalculateHash } from 'ua-cryptography';

const hash = dstu7564CalculateHash(new TextEncoder().encode('message'), 256);
```

A browser fetches it first, once (`ua_cryptography_bg.wasm` beside the module; bundlers such as Vite and webpack
copy it). `await init()` also works in Node.js, so one code path serves both:

```js
import init, { sign, verify, SignatureFormat, SignatureLevel, SignatureHash } from 'ua-cryptography';

await init();
const signature = sign(keyStore, password, undefined, [{ name: 'a.txt', content }], SignatureFormat.AsicE,
  SignatureLevel.B, SignatureHash.Dstu7564, false, []);
const report = verify(signature, [], [rootCertificate], []);   // report.is_valid
```

Bytes go in and come out as `Uint8Array`. TypeScript declarations are included.

### Time-stamps and revocation status online

`signOnline` and `verifyOnline` reach the PKI services with `fetch` and return a `Promise`:

```js
import { signOnline, verifyOnline } from 'ua-cryptography';

// Level T: the time-stamping service the signer's certificate names, or tsaUrl.
const signature = await signOnline(keyStore, password, undefined, [{ name: 'a.txt', content }],
  SignatureFormat.Cades, SignatureLevel.T, SignatureHash.Dstu7564, false, false, undefined, undefined, caCertificates);
// Asks the OCSP responders about the certificates the signature carries no status of, downloads missing CA
// certificates by caIssuers.
const report = await verifyOnline(signature, [], rootCertificates, caCertificates);
```

- A responder that does not answer — the network, CORS, a refused answer — leaves a `warning` on its revocation
  check; the signature still verifies. `signOnline` rejects with `ServiceFailure` instead: a signature at the level
  asked for cannot be made without the service.
- Only what the protocols need leaves the page: the hash of the signature value (time-stamp), the certificate's
  serial number and hashes of its issuer's name and key (OCSP).
- In a browser the services must allow the page's origin (CORS). The time-stamping and OCSP services of PrivatBank,
  "Diia", the Central Certification Authority and the NBU do; the NBU's caIssuers downloads do not, so pass its CA
  certificates in `certificates`. A page served over HTTPS asks the `http://` addresses of the certificates over
  `https://`; Node.js has neither restriction.

## API

| Area | Functions |
|---|---|
| GOST 28147-89 | `gost28147Encrypt`, `gost28147Decrypt` (simple substitution, any DKE) |
| GOST 34.311-95 | `gost34311CalculateHash`, `gost34311BeginHash` (any DKE and initial value) |
| DSTU 7564 | `dstu7564CalculateHash`, `dstu7564BeginHash` (256, 384, 512 bits); `HashState.update`, `HashState.end` |
| DSTU 7624 | `dstu7624EncryptBlock` / `DecryptBlock`; ECB, CBC, CFB, XTS `…Encrypt` / `…Decrypt`; `dstu7624OfbApplyGamma`, `dstu7624CtrApplyGamma`; CCM, GCM `…Encrypt` / `…Decrypt`; `dstu7624CmacCalculateMac`, `dstu7624GmacCalculateMac`; `dstu7624WrapKey`, `dstu7624UnwrapKey` |
| DSTU 4145 | `dstu4145GenerateKeyPair`, `dstu4145CalculatePublicKey`, `dstu4145ValidatePublicKey`, `dstu4145SignHash`, `dstu4145SignHashWithPresignature`, `dstu4145VerifyHash`, `dstu4145SignMessage`, `dstu4145VerifyMessage` (GOST 34.311), `dstu4145EncodeSignature`, `dstu4145DecodeSignature`, `dstu4145GenerateRandomBytes` (Appendix А) |
| key stores | `createKeyStore` (JKS, a key on a curve of table Г.1, a self-signed certificate), `getCertificate`, `getKeyStoreEntries` |
| certificates | `getCertificateDetails` |
| signatures | `sign` (CAdES, XAdES, ASiC-S, ASiC-E at level B), `verify` (any of them, offline, a report object); `signOnline` (levels B, T, LT, a content time-stamp), `verifyOnline` (OCSP and caIssuers online) |

DSTU 4145 takes integers big-endian (d, e, r, s and D = S‖R), Q compressed and a hash code most significant byte
first. The national PKI reverses its digests before signing and stores D reversed:
[signature-formats.md](https://github.com/ua-cryptography/ua-cryptography-rust/blob/main/docs/signature-formats.md).

A refusal is thrown as an `Error` whose `name` is the kind: `InvalidArgument`, `UnreadableInput`, `WrongPassword`,
`AuthenticationFailed`, `ServiceFailure`. An invalid signature is not a refusal: `verify` returns a report with
`is_valid: false`.

## Boundaries

- The network only through `signOnline` and `verifyOnline`; `sign` refuses levels T and LT with `InvalidArgument`.
- Revocation status by OCSP only: certificate revocation lists (CRL) are not read, as in the rest of the project.
- DSTU 4145 on the recommended curves of Appendix Г only.

## License

MIT. The DSTU 7624 modes are translated from BouncyCastle (MIT): see `THIRD-PARTY-NOTICES.md`.
