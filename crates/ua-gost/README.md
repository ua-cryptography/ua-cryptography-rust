# ua-gost

GOST 28147-89 block cipher and GOST 34.311-95 hash function with any substitution table (DKE).

## API

```rust
use ua_gost::{Gost28147, Gost34311, DEFAULT_DKE};

// One-shot hash with DKE No. 1; the result is H least significant byte first (reverse it for DSTU 4145, 5.6).
let hash: [u8; 32] = Gost34311::calculate_hash(b"message");

// The DKE of a certificate; a DKE that is not 64 bytes long is refused.
let mut hasher = Gost34311::from_dke(&DEFAULT_DKE)?;
hasher.update(b"mess");
hasher.update(b"age");
assert_eq!(hasher.finalize(), hash); // finalize resets the hasher for the next message

// The block cipher, e.g. for the generator of DSTU 4145-2002, Appendix А.
let mut cipher = Gost28147::new(&Gost28147::expand_dke(&DEFAULT_DKE)?)?;
cipher.set_key(&[0x11; 32]);
let ciphertext: [u8; 8] = cipher.encrypt_block(&[0; 8]);
assert_eq!(cipher.decrypt_block(&ciphertext), [0; 8]);
# Ok::<(), ua_gost::SubstitutionTableError>(())
```

| Item | What |
|---|---|
| `Gost28147::new(sbox: &[u8]) -> Result<Gost28147, SubstitutionTableError>` | the cipher over a 128-entry table (entry `v` of S-box `j` is `sbox[16 j + v]`) |
| `Gost28147::expand_dke(dke: &[u8]) -> Result<[u8; 128], SubstitutionTableError>` | a 64-byte DKE (high nibble first) as the 128-entry table |
| `Gost28147::default()` | the cipher over DKE No. 1 (zero key until `set_key`) |
| `Gost28147::set_key(&mut self, key: &[u8; 32])` | K0..K7, little-endian |
| `Gost28147::encrypt_block` / `decrypt_block(&self, &[u8; 8]) -> [u8; 8]` | simple substitution mode on one block |
| `Gost34311::new(sbox)`, `with_initial_value(sbox, &[u8; 32])`, `from_dke(dke)`, `default()` | the hash with a table, an H0, a DKE, DKE No. 1 |
| `Gost34311::update`, `finalize`, `reset`, `hash(&mut self, data)` | streaming; `hash` starts over and hashes `data` |
| `Gost34311::calculate_hash(data) -> [u8; 32]` | one-shot with DKE No. 1 |
| `DEFAULT_DKE: [u8; 64]` | DKE No. 1 |
| `SubstitutionTableError` | `WrongTableLength`, `EntryOutOfRange`, `WrongDkeLength` |

## Boundaries

- Only the simple substitution mode of GOST 28147-89, on single blocks: no gamming, no feedback modes, no MAC.
- No `digest::Digest` trait implementation; the PKI layer calls the hash directly.
- Keys and blocks are fixed-size arrays, so their lengths are checked by the caller's conversion, not here.

## Dependencies

None at run time. `serde_json` (dev) reads the BouncyCastle answers recorded in `testdata/oracle/gost-bc`.

## Visibility

Public: meant for crates.io, `publish = false` until the author decides.

## Why not a ready crate

RustCrypto's `gost94` and `magma` fix the substitution table at compile time, one type per named parameter set;
Ukrainian certificates carry an arbitrary DKE known only at run time, and DSTU 4145 needs the hash and the cipher over
the same table.

## Ported from

The C# namespace `UA.Cryptography.Gost` of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp).
