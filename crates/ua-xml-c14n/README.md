# ua-xml-c14n

Canonical XML 1.0 and Exclusive XML Canonicalization 1.0 over a `roxmltree` document, with the safe XML loading
XML-DSig verification needs.

## API

```rust
use ua_xml_c14n::{Algorithm, DocumentText};

let text = DocumentText::decode(xml_bytes)?;          // UTF-8 / UTF-16, line ends normalized
let document = text.parse()?;                          // DTDs refused
let signed_info = document
    .descendants()
    .find(|node| node.has_tag_name(("http://www.w3.org/2000/09/xmldsig#", "SignedInfo")))
    .unwrap();
let canonical: Vec<u8> = ua_xml_c14n::canonicalize(signed_info, Algorithm::Exclusive, &[], None);
```

| Item | What it does |
|---|---|
| `DocumentText::decode(&[u8]) -> Result<DocumentText, DocumentError>` | UTF-8 (BOM optional) or UTF-16 (with BOM) to text; `\r\n` and `\r` become `\n` (XML 1.0, 2.11) |
| `DocumentText::parse(&self) -> Result<roxmltree::Document, DocumentError>` | parses with DTDs refused and nesting limited to 64 levels |
| `canonicalize(node, Algorithm, inclusive_prefixes: &[&str], excluded: Option<Node>) -> Vec<u8>` | the canonical octets of `document.root()` or of one element in its document context |
| `Algorithm::{Inclusive, InclusiveWithComments, Exclusive, ExclusiveWithComments}`, `from_uri`, `uri` | the four methods by their XML-DSig URIs |
| `escape_text`, `escape_attribute` | C14N escaping, for XML built as text (it parses back unchanged) |
| `looks_like_xml(&[u8]) -> bool` | `<` after an optional UTF-8 BOM and white space |
| `roxmltree` | re-exported, so callers name the same `Document` and `Node` |

What `canonicalize` covers: whole documents (comments and PIs outside the document element on their own lines);
an element subtree with the namespaces in scope from its ancestors and, for inclusive C14N, the ancestors' `xml:*`
attributes (C14N 1.0, 2.4) — what a same-document reference `#id` hashes; the InclusiveNamespaces PrefixList of
exclusive C14N (`#default` for the default namespace); an excluded subtree (the enveloped-signature transform). Names
are sorted by UTF-16 code units, as the reference orders them. The walk uses an explicit stack.

## What `roxmltree` gives, and what is added here

- Attribute value normalization (tab, line feed → space; character references kept) and CDATA as text: as needed.
- Line ends: `roxmltree` normalizes text but not comments or PIs, and keeps a literal `\r` before a reference;
  `DocumentText::decode` normalizes the whole input before parsing, as XML 1.0, 2.11 describes.
- Prefixes: `roxmltree` keeps namespace URIs, not the prefixes written; element and attribute names are taken from the
  source text (`Node::range`, `Attribute::range`).
- Namespaces in scope come from `Node::namespaces()` (own declarations and inherited ones; `xmlns=""` as an empty
  default); `xml` is never among them, as C14N wants.
- DTDs: `ParsingOptions::allow_dtd = false` refuses them, so no entity is expanded and nothing external is read.
- Depth: the parser recurses per element, so `parse` refuses nesting deeper than 64 levels before parsing.

## Boundaries

- No writing of a DOM: `roxmltree` is read-only. Code that builds XML builds text with `escape_text` /
  `escape_attribute`, then decodes and parses it to canonicalize parts of it.
- No other transforms (XPath, XSLT, Canonical XML 1.1); a caller maps their URIs to refusals.
- Encodings: UTF-8 and UTF-16 only; a declaration naming another encoding is accepted only for ASCII text.

## Dependencies

`roxmltree` (read-only tree, DTDs refused). Tests: `serde_json` (oracle fixtures), `sha2` (reference digests).

## Visibility

Public: meant for crates.io, `publish = false` until the author decides.

## Why not a ready crate

Checked (crates.io, October 2026):

- `xml_c14n`, `xmlsec`: bind libxml2 / xmlsec1 (native code).
- `xml-sec` 0.1: a whole pure-Rust XML-DSig/XML-Enc stack on its own DOM, pulling `aws-lc-rs` (FIPS) and needing
  Rust 1.92 — far more than canonicalization, and young.
- `bergshamra-c14n` 0.9 / `ribergshamra-c14n` 0.11, `oxixml-c14n` 0.1: canonicalizers bound to their projects' own
  DOMs (`bergshamra-xml` + `uppsala`, `oxixml-dom`), young; adopting one means adopting its parser and its tree.
- `xml-canonicalization` 0.1: whole documents over `quick-xml` + `pest` + `regex`; no exclusive C14N, no subtrees.

Signatures depend on byte-exact agreement with the reference (a subtree in its document context, inherited `xml:*`,
name ordering); proving that for a foreign DOM and parser would cost as much as the canonicalizer itself, which is a
few hundred lines over `roxmltree` and is tested against Microsoft's `XmlDsigC14NTransform`,
`XmlDsigExcC14NTransform` and `SignedXml`.

## Ported from

The C# namespace `UA.Cryptography.Pki.Xml` (`XmlCanonicalizer`, `XmlSafe`) of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp). Tests:
`tests/canonicalizer_against_microsoft.rs` and `tests/canonicalizer_against_reference.rs` (recorded in
`testdata/oracle/c14n-microsoft`).
