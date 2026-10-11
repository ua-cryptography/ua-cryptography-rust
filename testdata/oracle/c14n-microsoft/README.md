# c14n-microsoft

Microsoft's canonicalization (`System.Security.Cryptography.Xml` 10.0.12) for every case the C#
`XmlCanonicalizerTests` checks, and the C# `XmlCanonicalizer`'s own output for every element subtree of those
documents and of a few documents that probe the parser.

Produced by `dotnet run --project tools/csharp-oracle -- c14n-microsoft`
(`tools/csharp-oracle/Generators/C14nMicrosoft.cs`) into `c14n-microsoft.json`. The generator refuses to write a case
where Microsoft and the C# canonicalizer disagree. Canonical forms are stored as JSON strings (UTF-8 text).

- `documents`: the nine test documents; `whole` maps each method URI to `XmlDsigC14NTransform` /
  `XmlDsigExcC14NTransform` output; `exclusiveSubtrees` gives, by element index in document order, the exclusive form
  of the element re-parsed from its `OuterXml` (elements with tabs or line ends in attributes skipped, as in the test);
  `target` is `SignedXml`'s SHA-256 digest of the reference `#target` and the canonical octets hashing to it.
- `prefixLists`: the exclusive form with the InclusiveNamespaces PrefixLists `b`, `#default`, `b #default`, `a b`.
- `enveloped`: the inclusive form of a document with its `ds:Signature` removed.
- `xades`: a XAdES-B-LT signature built by the C# test support (synthetic keys of `Hierarchy`), the exclusive form of
  every element and the inclusive form of the document.
- `reference`: for the test documents and eight probe documents (CR/LF in comments, PIs and text, PI white space,
  literal tabs and line ends in attributes, UTF-16 ordering of attribute namespaces, odd white space in tags,
  non-ASCII names, a BOM and XML declaration, default-namespace undeclaration), every method over the document and
  every element; `microsoftInclusiveWithComments` is Microsoft's whole-document output, for comparison.

Read by `crates/ua-xml-c14n/tests/canonicalizer_against_microsoft.rs` and
`crates/ua-xml-c14n/tests/canonicalizer_against_reference.rs`.
