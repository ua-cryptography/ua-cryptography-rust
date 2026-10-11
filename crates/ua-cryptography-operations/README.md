# ua-cryptography-operations

The operations behind the C ABI (`ua-cryptography-ffi`) and the JavaScript bindings (`ua-cryptography-wasm`): bytes
in, a model or an `OperationFailure` out.

## API

```rust
use ua_cryptography_operations::operations::{signing, verification};
use ua_cryptography_pki::SignatureServices;

let plan = signing::plan_signature(&request)?;                 // the key, the chain, the services the level needs
let services = SignatureServices {                              // the binding connects them
    extra_certificates: plan.extra_certificates.clone(),
    ..SignatureServices::default()
};
let signature = signing::sign(&request, &plan, &services)?;
let summary = verification::verify(&verification_request, None, None, now)?;   // offline
```

| Module | Operations |
|---|---|
| `operations::gost28147`, `gost34311`, `dstu7564`, `dstu7624`, `dstu4145` | the algorithms; `StreamingHash` for a hash fed in parts |
| `operations::key_store`, `certificate_details` | JKS stores with a DSTU 4145 key and a self-signed certificate; what a certificate says |
| `operations::signing` | `plan_signature`, then `sign`, or `prepare_signature` + `complete_signature` for a binding that fetches between them |
| `operations::verification` | `verify` with an OCSP service and caIssuers downloads, or none |
| `models` | the requests, the plan, `PendingSignature`, the JSON reports (`models::reports`) |

`FailureKind` decides the C status and the JavaScript error name; `to_json` writes a report.

## Boundaries

- No network and no platform: the services come in as the traits of `ua-cryptography-pki` (`TimeStampService`,
  `OcspService`, `CertificateSource`); the native binding passes its HTTP clients, the browser one what `fetch`
  brought.
- No C types and no JavaScript values: those are the bindings'.

## Dependencies

The workspace crates `ua-cryptography-gost`, `ua-cryptography-dstu7564`, `ua-cryptography-dstu7624`,
`ua-cryptography-dstu4145`, `ua-cryptography-gf2m`, `ua-cryptography-pki` (without its HTTP clients); `num-bigint`,
`rand_core`, `serde`, `serde_json`, `time`.

## Visibility

Internal to this workspace (`publish = false`): its API is the bindings', not a Rust API of its own.
