# package/

Signatures made by the C# package itself (the reference implementation), recorded by `tools/csharp-oracle -- pki`
with the `hierarchy/` signer and, for levels T and LT, the hierarchy's TSA and OCSP responders called in process
(`PkiLayer.Services`: `Tsa.StampHash`, the issuing CA's / root's responder by issuer), as the C# tests wire them.
Every file is in `../manifest.json` and was verified by the C# package; the CAdES files were also checked with the
BouncyCastle recipe of `UaPki` (messageDigest, signingCertificateV2, DSTU 4145 over the DER signed attributes).

| Files | What |
|-------|------|
| `data/` | `document.txt` = `"Документ для підпису"` (manifest name `content`); `zayava.txt` = file `заява.txt`; `data-file.bin` = file `data file.bin` (URI `data%20file.bin`); `contract.pdf`; `annex-tabl.csv` = file `annex/табл.csv` — the manifest maps each signed name to its file |
| `cades-{dstu7564,gost34311}-{enveloped,detached}-{b,t,lt}.p7s` | `CadesSigner.Sign(document, new CadesOptions(hash, detached, level))`; LT carries a content time-stamp too and is CAdES-X Long (references + values) |
| `asics-gost34311-t.asics` | `AsicContainer.CreateAsicS("contract.pdf", …, detached GOST CAdES-T)` |
| `xades-{dstu7564,gost34311}-{b,t,lt}.xml` | `XadesSigner.SignToBytes([заява.txt, data file.bin], hash, level)` |
| `asice-dstu7564-lt.asice` | `AsicContainer.CreateAsicE([contract.pdf, annex/табл.csv], XadesSigner.Sign(…, LT))` |
| `asice-dstu7564-b.asice` | the same at level B without services (the C# tests add or replace entries in it) |
| `twin-honest.p7s`, `twin-swapped.p7s` | signed attributes naming `hierarchy/signer-twin.cer`; honest carries the twin (valid), swapped carries `signer.cer` (invalid: `CMS: signing certificate` fails) |
| `caissuers-signer.cer`, `cades-t-no-tsa-certificate.p7s` | CAdES-T whose only certificate names caIssuers `http://ca.test/bundle.p7b` and whose token lacks the TSA certificate: valid offline with a warning; with the root and a download of [CA, TSA] fully valid |

Stands in for the C# package's output in `Pki/Cades/CadesSignerTests`, `Pki/Xades/XadesSignerTests`,
`Pki/Asic/AsicContainerTests`, `Pki/Tsp/TimeStampTokenTests`: the Rust tests sign with the Rust port at run time and
check it with Rust recipes; these files make sure the Rust verifier accepts what the reference implementation makes
(and give tampering tests a C#-made starting point).
