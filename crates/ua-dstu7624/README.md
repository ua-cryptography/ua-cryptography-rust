# ua-dstu7624

The DSTU 7624:2014 "Kalyna" block cipher and its modes (ECB, CBC, CFB, OFB, CTR, CMAC, CCM, GCM, GMAC, XTS, key
wrapping), translated from BouncyCastle Java 1.86 (`DSTU7624Engine`, `DSTU7624WrapEngine`, `DSTU7624Mac`, `KGMac`,
`KCTRBlockCipher`, `KCCMBlockCipher`, `KGCMBlockCipher`, `KXTSBlockCipher`; MIT licence, see THIRD-PARTY-NOTICES.md).

## API

```rust
use ua_dstu7624::{BlockSize, CipherFailure, Gcm, Kalyna};

let key = [0x2Au8; 32];
let gcm = Gcm::new(BlockSize::Bits128, &key)?; // a key of one or two blocks
let sealed = gcm.encrypt(b"nonce", b"header", b"secret", 128)?; // ciphertext ‖ 128-bit tag
assert_eq!(gcm.decrypt(b"nonce", b"header", &sealed, 128)?, b"secret");
assert_eq!(gcm.decrypt(b"nonce", b"other", &sealed, 128), Err(CipherFailure::TagMismatch));

let cipher = Kalyna::new(BlockSize::Bits256, &[0u8; 64])?;
let mut block = [0u8; 32];
cipher.encrypt_block(&mut block); // panics unless the slice is exactly one block
cipher.decrypt_block(&mut block);
# Ok::<(), Box<dyn std::error::Error>>(())
```

| Type | Constructor | Operations |
|---|---|---|
| `Kalyna` | `new(BlockSize, key) -> Result<_, SetupError>` | `encrypt_block`, `decrypt_block(&self, &mut [u8])`, `block_size`, `block_bytes` |
| `Ecb` | `new(BlockSize, key)` | `encrypt`, `decrypt(data)` — whole blocks |
| `Cbc` | `new(BlockSize, key)` | `encrypt`, `decrypt(iv, data)` — whole blocks, a one-block IV |
| `Cfb` | `new(BlockSize, key)`, `with_segment(.., segment_bits)` | `encrypt`, `decrypt(iv, data)` |
| `Ofb` | `new(BlockSize, key)`, `with_segment(.., segment_bits)` | `apply_gamma(iv, data)` |
| `Ctr` | `new(BlockSize, key)` | `apply_gamma(iv, data)` |
| `Cmac` | `new(BlockSize, key, mac_bits)` | `calculate_mac(data)` — a non-empty whole number of blocks |
| `Gmac` | `new(BlockSize, key)` | `calculate_mac(nonce, data, mac_bits)` |
| `Gcm` | `new(BlockSize, key)` | `encrypt`, `decrypt(nonce, associated_data, data, mac_bits)` |
| `Ccm` | `new(BlockSize, key)` (Nb = 4), `with_nb(.., nb)` | `encrypt`, `decrypt(nonce, associated_data, data, mac_bits)` |
| `Xts` | `new(BlockSize, key)` | `encrypt`, `decrypt(iv, data)` — whole blocks, a one-block IV |
| `KeyWrap` | `new(BlockSize, key)` | `wrap_key(data)`, `unwrap_key(wrapped)` |

Every operation returns `Result<Vec<u8>, CipherFailure>`; the constructors refuse with `SetupError`.
`BlockSize::{Bits128, Bits256, Bits512}`, `BlockSize::from_bits(usize)`.

The round transformations are BouncyCastle's bit-sliced form: MixColumns and its inverse as rotations and byte-wise
multiplications by x on 64-bit columns, ShiftRows as masked swaps; the S-boxes come from `ua-dstu-sboxes`.

## Boundaries

- Whole messages only: BouncyCastle's streaming interface is not reproduced.
- No padding schemes; ECB, CBC, XTS, CMAC and key wrapping take whole blocks.
- Lengths in CCM and GCM are counted in 32 bits, as BouncyCastle counts them.
- No `cipher`/`aead` trait implementations.

## Dependencies

`ua-dstu-sboxes` (π0..π3 and their inverses). `serde_json` (dev) reads the 590 BouncyCastle Java vectors of
`testdata/vectors/dstu7624-bc-java-1.86.json`.

## Visibility

Public: meant for crates.io, `publish = false` until the author decides.

## Why not a ready crate

Block-cipher crates for Kalyna, where they exist, stop at the cipher; the modes of DSTU 7624 (its own CTR, CCM,
GCM with GF(2^256)/GF(2^512), XTS, key wrapping) have no ready Rust implementation.

## Ported from

`UA.Cryptography.Dstu7624` of [ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp),
itself translated from BouncyCastle Java 1.86 (classes listed above).
