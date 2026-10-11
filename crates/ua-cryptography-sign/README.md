# ua-cryptography-sign

The `ua-sign` command-line tool: DSTU 4145 keys in JKS key stores, signing and verification in CAdES, XAdES, ASiC-S
and ASiC-E at levels B, T and LT, built on `ua-cryptography-pki`.

## Usage

The commands, options, output, INI report and exit codes are described in
[docs/ua-sign.md](https://github.com/ua-cryptography/ua-cryptography-rust/blob/main/docs/ua-sign.md).

```bash
ua-sign keygen --keystore key.jks --subject "CN=Name,O=Organization,C=UA" --cert key.cer
ua-sign sign --keystore key.jks --format asic-e --in contract.pdf --level T --tsa http://tsp.example/
ua-sign verify --in contract.pdf.asice --trust czo-root.cer --format ini --report report.ini
```

Exit codes: 0 — done / the signature is valid, 1 — the signature is invalid, 2 — a usage or processing error.
The scripts in `build_scripts/` wrap it (`ua-sign.sh`, `publish.sh`, `demo.sh`, `keygen.sh`, `sign.sh`, `verify.sh` and
their `.ps1` twins; `interop.sh` checks it against the C# `ua-sign`).

## API

The binary is a thin `main.rs`; the command logic is a library function the tests call in process:

```rust
pub fn run(args: &[String], output: &mut dyn Write, error: &mut dyn Write,
           environment: &dyn Fn(&str) -> Option<String>) -> u8;
pub const EXIT_VALID: u8 = 0;
pub const EXIT_INVALID: u8 = 1;
pub const EXIT_ERROR: u8 = 2;
```

```rust
let mut output = Vec::new();
let mut error = Vec::new();
let args = ["verify", "--in", "doc.txt.p7s"].map(String::from);
let code = ua_cryptography_sign::run(&args, &mut output, &mut error, &|name| std::env::var(name).ok());
```

Inside: `arguments` (the options of a command, parsed by hand), `passwords` (`--password`, `--password-env`,
`--password-file` or the terminal without echo), `report` (text and INI), `commands/` (one file per command),
`files` (file access and paths normalized by name, so that a reference like `../../secret` is not followed),
`errors/` (`UsageError`: shown with the command's help; `CommandFailure`: everything that stops a command).

## Boundaries

- No PAdES, PKCS#12, JCEKS or IIT key containers, CRLs, archive time-stamps (see docs/ua-sign.md, "What is not
  supported"); everything signature-related is `ua-cryptography-pki`'s.
- The key entry is opened with the store's password, as in the stores Ukrainian banks issue.
- Messages of errors are the libraries' (`ua-cryptography-pki`) and the operating system's; they are not localized.

## Dependencies

`ua-cryptography-pki` (everything PKI), `ua-cryptography-dstu4145` (the curves of table Г.1), `ua-cryptography-gf2m`
(the basis of a key's field, shown), `num-bigint` (serial numbers), `time` (dates), `rpassword` (the terminal password
without echo). Tests: `serde_json` (the hierarchy's keys recorded by `tools/csharp-oracle`), `ua-cryptography-der`,
`ua-cryptography-gost`, `ua-cryptography-dstu7564`, `ua-cryptography-xml-c14n`, `roxmltree`, `base64` (independent
recipes for the provider profiles), `zip` (rewriting containers).

## Visibility

Public: the crates.io package `ua-cryptography-sign`, published by the author; `cargo install ua-cryptography-sign`
installs the `ua-sign` command.

## Why not a ready crate

Argument parsing is by hand, as in the C# tool, rather than `clap`: four commands with a handful of `--name value`
options and flags, the exact usage messages of the reference, and no dependency for it.

## Tests

`tests/ua_sign.rs` ports `Cli/UaSignTests` (every fact and theory row), `tests/provider_formats.rs` the command-line
side of `Signatures/ProviderFormatTests` (PrivatBank `.sig` and "Дія" ASiC-E, made by ua-sign and as the providers
make them). Levels T and LT go over HTTP to `tests/common/local_server.rs`, a small server on `std::net::TcpListener`
with the time-stamping service, OCSP responders and caIssuers bundle of the synthetic hierarchy
(`testdata/oracle/pki/hierarchy/keys.json`); the bank's recorded `.sig` names its services at `127.0.0.1:18089`, so
that one test serves on that fixed port. `tests/pki_server.rs` is not a test: run with `--ignored` and
`UA_SIGN_TEST_PKI_DIRECTORY`, it serves that PKI for `build_scripts/interop.sh`.

## Ported from

`UA.Cryptography.Cli` (Program, Arguments, UaSign, Passwords, Report) and `scripts/` of
[ua-cryptography-csharp](https://github.com/ua-cryptography/ua-cryptography-csharp).
