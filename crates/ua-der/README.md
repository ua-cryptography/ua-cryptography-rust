# ua-der

A DER/BER reader that keeps the exact bytes of every element, a DER writer made of small functions, and PEM — the
ASN.1 layer of the Ukrainian PKI crates.

## API

```rust
use ua_der::{Asn1Node, tag};

// Writing: every function returns one complete element; constructed values nest calls.
let spki = ua_der::sequence([
    ua_der::algorithm_identifier("1.2.804.2.1.1.1.1.3.1.1"),
    ua_der::bit_string(&ua_der::octet_string(&[0x01, 0x02])),
]);

// Reading: nodes are slices of the input, children are parsed when asked for.
let node = Asn1Node::parse(&spki)?.expect_tag(tag::SEQUENCE)?;
let fields = node.children()?;
assert_eq!(fields[0].child(0)?.to_oid()?, "1.2.804.2.1.1.1.1.3.1.1");
let signed_bytes: &[u8] = node.encoded(); // exactly as received, for hashing
# Ok::<(), ua_der::DerError>(())
```

| Item | What it does |
|---|---|
| `Asn1Node::parse` / `parse_first` | exactly one element / the first element of the data |
| `tag`, `encoded`, `content`, `is_constructed`, `is_context(n)`, `has_tag`, `expect_tag` | the element and its identifier |
| `children`, `child(i)` | the children of a constructed element (depth limited to 64) |
| `to_integer` (`BigInt`), `to_unsigned_integer` (`BigUint`), `to_i32`, `to_boolean`, `to_oid`, `to_octet_string` (BER segments joined), `to_bit_string`, `to_named_bits`, `to_text`, `to_time` (`OffsetDateTime`, UTC) | typed values; any malformation is a `DerError` |
| `encode`, `sequence`, `set_of` (sorted, X.690 11.6), `boolean`, `null`, `integer`, `integer_from_unsigned`, `integer_from_i64`, `octet_string`, `bit_string`, `named_bits`, `utf8_string`, `printable_string`, `ia5_string`, `utc_time`, `generalized_time`, `x509_time`, `object_identifier`, `algorithm_identifier`, `explicit`, `implicit` | the DER writer |
| `encode_oid` / `decode_oid` | dotted-decimal text ↔ contents octets (`OidError` for bad text) |
| `decode_pem` / `encode_pem` | DER, PEM or bare base64 in → DER out (`PemError`); DER → PEM text |
| `tag::*` | identifier octets of the universal types, `context_constructed(n)`, `context_primitive(n)` |

`object_identifier` and `algorithm_identifier` are for the OID constants of the code and panic on malformed text;
text from outside (a distinguished name typed by a user) goes through `encode_oid` first.

## Reading rules

- DER and the BER forms CMS uses: indefinite lengths (constructed only), constructed OCTET STRINGs, non-minimal
  length octets. Lengths up to 2^31 − 1, at most four length octets.
- Refused: truncated data, trailing bytes after `parse`, high tag numbers (31+), indefinite primitive elements, missing
  end-of-contents octets, nesting deeper than 64 levels.
- Character strings decode leniently (an undecodable sequence becomes U+FFFD); PrintableString, IA5String,
  NumericString, VisibleString and TeletexString are read as Latin-1.
- Times: UTCTime `YYMMDDhhmm[ss]`, GeneralizedTime `YYYYMMDDhhmm[ss[.fffffff]]` (`,` accepted for `.`), each with
  `Z`, `±hhmm` (up to ±14:00) or no zone (read as UTC); UTCTime years 50–99 are 19YY (RFC 5280, 4.1.2.5.1).

## Boundaries

- No schema, no derive: callers walk the tree by index, as the PKI structures are read.
- No high tag numbers, no REAL, no streaming input. The writer emits DER only.
- Written times are whole seconds in UTC.

## Dependencies

`num-bigint` (INTEGER values, OID arcs of any size), `time` (UTC date-times), `base64` (PEM). Tests: `serde_json`
for the oracle fixtures.

## Visibility

Public: meant for crates.io, `publish = false` until the author decides.

## Why not a ready crate

Checked against the need — a tree of slices over the original bytes, BER indefinite lengths accepted, every element's
exact encoding available for signature checks:

- [`der`](https://crates.io/crates/der) (RustCrypto) is strict DER: its length decoder refuses the indefinite form
  (`ErrorKind::IndefiniteLength`), and its model is typed and derive-driven; CMS from Ukrainian tools arrives in BER.
- [`asn1-rs`](https://crates.io/crates/asn1-rs) reads BER, but its `Any` keeps the header and the contents, not the
  exact encoded slice of the element.
- [`bcder`](https://crates.io/crates/bcder) and [`yasna`](https://crates.io/crates/yasna) read BER through
  closure-driven decoders (raw bytes via `Captured` / tagged values on request); the PKI layer reads structures by
  index, as the reference does, and would wrap them anyway.

The reader, the writer and PEM here are about a thousand lines, tested against BouncyCastle.

## Ported from

The C# namespace `UA.Cryptography.Pki.Asn1` (`Asn1Node`, `Asn1Tag`, `Der`, `Pem`) of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp). Tests:
`tests/der_against_bouncy_castle.rs` (BouncyCastle's encodings recorded in `testdata/oracle/der-bc`),
`tests/reader_and_writer.rs`.
