# ua-cryptography-dstu-sboxes

The four S-boxes π0..π3 of DSTU 7564:2014 (Kupyna) and DSTU 7624:2014 (Kalyna), and their inverses.

## API

```rust
use ua_cryptography_dstu_sboxes::{INVERSE_PI, PI};

let substituted = PI[2][0x00];
assert_eq!(INVERSE_PI[2][usize::from(substituted)], 0x00);
```

| Item | What |
|---|---|
| `PI: [[u8; 256]; 4]` | π0..π3 as the standards print them |
| `INVERSE_PI: [[u8; 256]; 4]` | their inverses, computed at compile time |

## Boundaries

Tables only: the round functions and the lookup tables built from these S-boxes live in `ua-cryptography-dstu7564` and
`ua-cryptography-dstu7624`.

## Dependencies

None.

## Visibility

Public: the crates.io package `ua-cryptography-dstu-sboxes`, published by the author. It exists as a crate so the two
algorithms share one copy of the tables without depending on each other.

## Ported from

`UA.Cryptography.Common.DstuSBoxes` (internal there) of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp); the tables were taken from
BouncyCastle Java 1.86 (see THIRD-PARTY-NOTICES.md).
