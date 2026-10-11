# ua-cryptography-wasm

The operations of `ua-cryptography-operations` for JavaScript, in WebAssembly: the npm package
[`ua-cryptography`](https://www.npmjs.com/package/ua-cryptography) for browsers and Node.js.

## API

The functions and their use are in [npm/README.md](npm/README.md), the package's README; every operation of the C ABI
of `ua-cryptography-ffi` is here under its camelCase name (`ua_dstu7564_calculate_hash` is `dstu7564CalculateHash`).

```js
import init, { signOnline, verifyOnline, SignatureFormat, SignatureLevel, SignatureHash } from 'ua-cryptography';

await init();
const signature = await signOnline(keyStore, password, undefined, [{ name: 'a.txt', content }],
  SignatureFormat.Cades, SignatureLevel.T, SignatureHash.Dstu7564, false, false, undefined, undefined, []);
const report = await verifyOnline(signature, [], [rootCertificate], []);   // report.is_valid
```

| File | What it holds |
|---|---|
| `src/js_exports.rs`, `src/js_exports/` | what WASM exports to JS: the `#[wasm_bindgen]` functions, one area per file; reading `NamedBytes[]` and `Uint8Array[]`; a refusal as an `Error` named after its kind |
| `src/js_imports.rs` | what WASM imports from JS: the global `fetch` and `AbortSignal.timeout`, and the POST / GET of the PKI services over them |
| `src/service_answers.rs` | the services' answers behind the synchronous traits of `ua-cryptography-pki` |

### Online, over synchronous signers

`ua-cryptography-pki` asks its services synchronously; `fetch` answers asynchronously. `signOnline` and `verifyOnline`
run the synchronous operation against `ServiceAnswers`, which writes down every question it cannot answer yet and
refuses it; the questions are then fetched at once (`Promise`s in flight together) and the operation runs again,
until it asks nothing new — at most 12 runs. A run repeats only what does not depend on chance: the signature value is
made once (`prepare_signature`), and only the step that asks the time-stamp over it repeats (`complete_signature`).
The asynchrony stays in this crate.

A failed request is an answer: the verifier reports a warning on that certificate's revocation check, a signer
refuses with `ServiceFailure`.

## Boundaries

- The browser decides what a page may reach: a service must allow the page's origin (CORS); a page served over HTTPS
  asks the certificates' `http://` addresses over `https://` (mixed content is blocked otherwise). Node.js does
  neither.
- No CRLs; no proxy or transport of the host's own: `fetch` as the engine provides it.
- The JavaScript API is this crate's own: a change of it is a change of the package's version.

## Dependencies

`ua-cryptography-operations`, `ua-cryptography-pki` (without its HTTP clients); `wasm-bindgen`, `js-sys`,
`wasm-bindgen-futures`, `num-bigint` and `rand_core` (the requests' nonces), `getrandom` and `time` with their browser
features. Tool: `wasm-pack` (`build_scripts/npm-package.sh`).

## Tests

- `cargo test -p ua-cryptography-wasm`: the bookkeeping of `ServiceAnswers`, natively.
- `build_scripts/npm-smoke-test.sh TARBALL`: the packed package as a user installs it (`tests/js/smoke_test.mjs`).
- `build_scripts/npm-online-test.sh TARBALL`: `signOnline` and `verifyOnline` against the test PKI server of
  `ua-cryptography-sign` (`tests/js/online_test.mjs`): levels T and LT in every format, caIssuers, OCSP, an
  unreachable responder.

## Visibility

Private to this workspace (`publish = false` for crates.io); the package goes to npm by the release workflow once the
author approves.

## Why not a ready crate

`web-sys` binds `fetch` too, with every Web API type around it; the two imports here (`fetch`, `AbortSignal.timeout`)
and `Response`'s four members are declared directly, and the global `fetch` serves Node.js as well as the browser.
