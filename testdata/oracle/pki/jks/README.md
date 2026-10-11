# jks/

Sun JKS key stores with DSTU 4145 keys, recorded by `tools/csharp-oracle -- pki`. `jks.json` lists every store:
file, writer, store and key passwords, entries (alias — also as UTF-16 code units in hex —, type, `m`, `d`, public
point, DKE, the certificate chain as files in stored order), the expected signing chain or error, and the C# tests.

Writers: `Support/Jks.cs` is the independent test implementation (BouncyCastle ASN.1, single PrivateKeyEntry,
UTF-8 aliases); stores it cannot write (several entries, modified UTF-8, separate key password) come from the C#
package's `JksKeyStore` and were read back by it.

| File | Writer | Case | C# test |
|------|--------|------|---------|
| `test-impl-signer.jks` | Jks.cs | the hierarchy signer with [signer, CA, root] | `JksKeyStoreTests.StoreWrittenByTheTestImplementationIsReadByThePackage`, `TestPkiTests.JksRoundTripRecoversKeyAndChain` |
| `test-impl-root-first-agreement.jks` + `agreement.cer` | Jks.cs | `pb_sign`: [root, CA, signer, key-agreement certificate] → signing chain [signer, CA, root] | `JksKeyStoreTests.ChainStoredRootFirstWithAKeyAgreementCertificateIsReordered` |
| `test-impl-key-matches-no-certificate.jks` | Jks.cs | the agreement key with [root, CA, signer] → InvalidDataException | same test, second half |
| `test-impl-key-certificate-mismatch.jks` | Jks.cs | the signer's key with the CA's certificate → InvalidDataException | `JksKeyStoreTests.KeyThatDoesNotMatchItsCertificateIsRejected` |
| `test-impl-password-right.jks` + `standalone.cer` | Jks.cs | password `right`; `wrong` fails | `TestPkiTests.JksWithWrongPasswordIsRejected` |
| `package-signer.jks` | package | read back by Jks.cs | `JksKeyStoreTests.StoreWrittenByThePackageIsReadByTheTestImplementation` (reverse direction: the Rust reader reads the C# writer) |
| `package-several-entries.jks` + `several-entries-*.cer` | package | `підпис`, `nul\u0000char` (C0 80), `emoji 🔑`, trusted `root` | `JksKeyStoreTests.SeveralEntriesAndUnusualAliasesRoundTrip` |
| `package-key-password.jks` | package | store password ≠ key password `key password` | `JksKeyStoreTests.WrongPasswordsAndDamageAreDetected` |
| `pkcs8-octet-string.der`, `pkcs8-integer.der` | package / BouncyCastle | PKCS#8 with d little-endian in an OCTET STRING, and the BouncyCastle form (OCTET STRING wrapping an INTEGER) | `JksKeyStoreTests.Pkcs8AcceptsTheBouncyCastleIntegerForm` |

Passwords: `correct horse battery staple` unless `jks.json` says otherwise. Damage (flipped bytes) is done by the
Rust tests. The Rust test of "the package's store is read by the test implementation" needs an independent reader;
the C# one is `Support/Jks.cs` (SHA-1 key protector, ~150 lines) — these stores let the Rust reader be checked
against both C# writers instead.
