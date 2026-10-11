using System.Security.Cryptography;
using System.Text.Json.Nodes;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.KeyStore;
using UA.Cryptography.Pki.X509;
using static CSharpOracle.Generators.PkiOutput;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;
using Oids = UA.Cryptography.Tests.Support.Oids;

namespace CSharpOracle.Generators;

/// <summary>
/// jks/: key stores written by the independent test implementation (Support/Jks.cs) and by the C# package for each case
/// of JksKeyStoreTests and TestPkiTests, with passwords and expected contents, plus the two PKCS#8 forms.
/// </summary>
internal static class JksFixtures
{
    private const string Password = "correct horse battery staple";

    public static void Write(PkiOutput o)
    {
        Hierarchy pki = o.Pki;
        var stores = new JsonArray();
        List<BcCertificate> chain = [.. pki.SignerChain];

        // Support/Jks.cs: the signer with its chain.
        string signer = o.Write("jks/test-impl-signer.jks", Jks.Write("signer", pki.Signer.Key, chain, Password));
        CheckPackageReads(o, signer, Password, "signer", pki.Signer.Key, chain.Count);
        stores.Add(Store(o, signer, "Support/Jks.cs", Password, null, [Entry(o, "signer", pki.Signer.Key, chain)],
            "the signer with signer, CA, root; SigningKey.FromJks picks it",
            ["Pki/KeyStore/JksKeyStoreTests.StoreWrittenByTheTestImplementationIsReadByThePackage", "Pki/TestPkiTests.JksRoundTripRecoversKeyAndChain",
                "Pki/TestPkiTests.JksWithWrongPasswordIsRejected (any other password)"]));

        // Support/Jks.cs: as PrivatBank issues keys: root, CA, the signing certificate, then a key-agreement certificate.
        TestPki.TestKey agreementKey = TestPki.GenerateKey(431);
        Certificate agreement = new CertificateBuilder(pki.Signer.Certificate.ToPki().Subject, agreementKey.ToPki().PublicKey)
            .AddKeyUsage(KeyUsageFlags.KeyAgreement).Issue(pki.IssuingCa.Certificate.ToPki(), pki.IssuingCa.Key.ToPki());
        string agreementFile = o.WriteCertificate("jks/agreement.cer", agreement.Encoded);
        BcCertificate bcAgreement = UaPki.ParseCertificate(agreement.Encoded);
        List<BcCertificate> rootFirst = [pki.Root.Certificate, pki.IssuingCa.Certificate, pki.Signer.Certificate, bcAgreement];
        string rootFirstFile = o.Write("jks/test-impl-root-first-agreement.jks", Jks.Write("pb_sign", pki.Signer.Key, rootFirst, Password));
        SigningKey reordered = SigningKey.FromJks(JksKeyStore.Load(o.Read(rootFirstFile), Password), Password);
        Expect(reordered.Chain.Select(c => c.Encoded).SequenceEqual(chain.Select(c => c.GetEncoded()), ByteArrays), "root-first chain is reordered");
        stores.Add(Store(o, rootFirstFile, "Support/Jks.cs", Password, null, [Entry(o, "pb_sign", pki.Signer.Key, rootFirst)],
            "chain stored root first with a key-agreement certificate (agreement.cer, keyUsage keyAgreement, made by the package's CertificateBuilder); SigningKey.FromJks yields [signer, CA, root]",
            ["Pki/KeyStore/JksKeyStoreTests.ChainStoredRootFirstWithAKeyAgreementCertificateIsReordered"],
            expectedSigningChain: chain.Select(o.FileOf)));

        List<BcCertificate> withoutAgreement = [pki.Root.Certificate, pki.IssuingCa.Certificate, pki.Signer.Certificate];
        string otherFile = o.Write("jks/test-impl-key-matches-no-certificate.jks", Jks.Write("other", agreementKey, withoutAgreement, Password));
        ExpectThrows<InvalidDataException>(() => SigningKey.FromJks(JksKeyStore.Load(o.Read(otherFile), Password), Password), "no matching certificate");
        stores.Add(Store(o, otherFile, "Support/Jks.cs", Password, null, [Entry(o, "other", agreementKey, withoutAgreement)],
            "the key-agreement key with root, CA, signer: no certificate matches the key, SigningKey.FromJks throws InvalidDataException",
            ["Pki/KeyStore/JksKeyStoreTests.ChainStoredRootFirstWithAKeyAgreementCertificateIsReordered (second half)"],
            expectedError: "InvalidDataException from SigningKey.FromJks"));

        // Support/Jks.cs: a key with another identity's certificate.
        List<BcCertificate> caOnly = [pki.IssuingCa.Certificate];
        string mismatch = o.Write("jks/test-impl-key-certificate-mismatch.jks", Jks.Write("mismatch", pki.Signer.Key, caOnly, Password));
        ExpectThrows<InvalidDataException>(() => JksKeyStore.Load(o.Read(mismatch), Password).PrivateKeys.Single().GetPrivateKey(Password), "mismatch");
        stores.Add(Store(o, mismatch, "Support/Jks.cs", Password, null, [Entry(o, "mismatch", pki.Signer.Key, caOnly)],
            "the signer's key with the issuing CA's certificate: GetPrivateKey throws InvalidDataException",
            ["Pki/KeyStore/JksKeyStoreTests.KeyThatDoesNotMatchItsCertificateIsRejected"], expectedError: "InvalidDataException from GetPrivateKey"));

        // Support/Jks.cs: a standalone self-signed key, password "right".
        TestPki.TestIdentity standalone = TestPki.CreateSelfSigned("CN=Signer,C=UA");
        string standaloneCert = o.WriteCertificate("jks/standalone.cer", standalone.Certificate.GetEncoded());
        string right = o.Write("jks/test-impl-password-right.jks", Jks.Write("signer", standalone.Key, [standalone.Certificate], "right"));
        ExpectThrows<CryptographicException>(() => JksKeyStore.Load(o.Read(right), "wrong"), "wrong store password");
        CheckPackageReads(o, right, "right", "signer", standalone.Key, 1);
        stores.Add(Store(o, right, "Support/Jks.cs", "right", null, [Entry(o, "signer", standalone.Key, [standalone.Certificate])],
            $"self-signed key (CN=Signer,C=UA, GOST 34.311 signature, {standaloneCert}) with password \"right\"; \"wrong\" fails the integrity check",
            ["Pki/TestPkiTests.JksWithWrongPasswordIsRejected"]));

        // The C# package: the signer with its chain, read back by Support/Jks.cs.
        var store = new JksKeyStore();
        store.AddPrivateKey("signer", pki.Signer.Key.ToPki(), chain.Select(c => c.ToPki()).ToList(), Password);
        string package = o.Write("jks/package-signer.jks", store.Save(Password));
        Jks.Entry read = Jks.Read(o.Read(package), Password);
        Expect(read.Alias == "signer" && read.Key.PrivateKey == pki.Signer.Key.PrivateKey
            && read.Chain.Select(c => c.GetEncoded()).SequenceEqual(chain.Select(c => c.GetEncoded()), ByteArrays), "Support/Jks.cs reads the package's store");
        stores.Add(Store(o, package, "C# package JksKeyStore", Password, null, [Entry(o, "signer", pki.Signer.Key, chain)],
            "written by the C# package and read back by Support/Jks.cs (alias, d, chain)",
            ["Pki/KeyStore/JksKeyStoreTests.StoreWrittenByThePackageIsReadByTheTestImplementation (reverse direction)"]));

        // The C# package: several entries with unusual aliases and a trusted certificate.
        stores.Add(SeveralEntries(o));

        // The C# package: a key password different from the store password.
        var keyPassword = new JksKeyStore();
        keyPassword.AddPrivateKey("signer", pki.Signer.Key.ToPki(), [pki.Signer.Certificate.ToPki()], "key password");
        string keyPasswordFile = o.Write("jks/package-key-password.jks", keyPassword.Save(Password));
        JksPrivateKeyEntry entry = JksKeyStore.Load(o.Read(keyPasswordFile), Password).PrivateKeys.Single();
        ExpectThrows<CryptographicException>(() => entry.GetPrivateKey(Password), "store password does not open the key");
        Expect(entry.GetPrivateKey("key password").D == pki.Signer.Key.PrivateKey, "key password opens the key");
        stores.Add(Store(o, keyPasswordFile, "C# package JksKeyStore", Password, "key password",
            [Entry(o, "signer", pki.Signer.Key, [pki.Signer.Certificate])],
            "store password and key password differ: the store password fails the key protector (CryptographicException); \"wrong\" fails the integrity check",
            ["Pki/KeyStore/JksKeyStoreTests.WrongPasswordsAndDamageAreDetected"]));

        o.WriteJson("jks/jks.json", new JsonObject
        {
            ["about"] = "d, qx, qy: big-endian hex; aliases also as UTF-16 code units (hex) since some are not printable",
            ["stores"] = stores,
            ["pkcs8"] = Pkcs8(o),
        });
        o.WriteText("jks/README.md", Readme);
    }

    private static JsonObject SeveralEntries(PkiOutput o)
    {
        string[] aliases = ["підпис", "nul\u0000char", "emoji \U0001F511"];
        var store = new JksKeyStore();
        var entries = new List<JsonObject>();
        for (int i = 0; i < aliases.Length; i++)
        {
            TestPki.TestKey key = TestPki.GenerateKey(257);
            Certificate certificate = new CertificateBuilder(DistinguishedName.Parse($"CN=Key {aliases[i].Length}"), key.ToPki().PublicKey).SelfSign(key.ToPki());
            o.WriteCertificate($"jks/several-entries-{i + 1}.cer", certificate.Encoded);
            store.AddPrivateKey(aliases[i], key.ToPki(), [certificate], Password);
            entries.Add(Entry(o, aliases[i], key, [UaPki.ParseCertificate(certificate.Encoded)]));
        }
        store.AddTrustedCertificate("root", o.Pki.Root.Certificate.ToPki());
        entries.Add(new JsonObject
        {
            ["alias"] = "root",
            ["aliasUtf16"] = Utf16("root"),
            ["type"] = "trustedCertificate",
            ["certificate"] = o.RootFile,
        });
        byte[] saved = store.Save(Password);
        string file = o.Write("jks/package-several-entries.jks", saved);

        JksKeyStore read = JksKeyStore.Load(saved, Password);
        Expect(read.Entries.Select(e => e.Alias).SequenceEqual([.. aliases, "root"]), "aliases round-trip");
        Expect(saved.AsSpan().IndexOf((ReadOnlySpan<byte>)[(byte)'n', (byte)'u', (byte)'l', 0xC0, 0x80]) > 0, "U+0000 as C0 80");
        ExpectThrows<ArgumentException>(() => SigningKey.FromJks(read, Password), "several keys need an alias");
        Expect(SigningKey.FromJks(read, Password, "ПІДПИС").Certificate.Equals(read.PrivateKeys.First().Chain[0]), "alias is case-insensitive");

        return Store(o, file, "C# package JksKeyStore", Password, null, entries,
            "three private keys (self-signed, m = 257) with aliases \"підпис\", \"nul\\u0000char\" (Java modified UTF-8: C0 80) and \"emoji 🔑\" (a surrogate pair: two 3-byte sequences), then a trusted certificate \"root\"; SigningKey.FromJks without alias throws ArgumentException, with \"ПІДПИС\" picks the first",
            ["Pki/KeyStore/JksKeyStoreTests.SeveralEntriesAndUnusualAliasesRoundTrip"]);
    }

    private static JsonObject Pkcs8(PkiOutput o)
    {
        TestPki.TestKey key = TestPki.GenerateKey(257);
        Dstu4145PrivateKey pkiKey = key.ToPki();
        byte[] standard = pkiKey.ToPkcs8();
        var sequence = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(standard);
        byte[] bcForm = new Org.BouncyCastle.Asn1.DerSequence(sequence[0], sequence[1],
            new Org.BouncyCastle.Asn1.DerOctetString(new Org.BouncyCastle.Asn1.DerInteger(
                new Org.BouncyCastle.Math.BigInteger(1, key.PrivateKey.ToByteArray(true, true))))).GetDerEncoded();
        Expect(Dstu4145PrivateKey.FromPkcs8(bcForm).D == key.PrivateKey, "the package reads the INTEGER form");
        Expect(Dstu4145PrivateKey.FromPkcs8(standard).D == key.PrivateKey, "the package reads its own form");
        Expect(Jks.BuildPkcs8(key).AsSpan().SequenceEqual(standard), "Support/Jks.cs and the package agree on PKCS#8");
        return new JsonObject
        {
            ["standard"] = o.Write("jks/pkcs8-octet-string.der", standard),
            ["bouncyCastle"] = o.Write("jks/pkcs8-integer.der", bcForm),
            ["d"] = Hex(key.PrivateKey),
            ["m"] = key.M,
            ["about"] = "PrivateKeyInfo { 0, { DSTU 4145 LE OID, { named curve, DKE } }, privateKey }: the standard form holds d little-endian in an OCTET STRING (C# package and Support/Jks.cs agree byte for byte); the BouncyCastle form holds an OCTET STRING wrapping the DER INTEGER d (Pki/KeyStore/JksKeyStoreTests.Pkcs8AcceptsTheBouncyCastleIntegerForm)",
        };
    }

    private static JsonObject Entry(PkiOutput o, string alias, TestPki.TestKey key, IEnumerable<BcCertificate> chain) => new()
    {
        ["alias"] = alias,
        ["aliasUtf16"] = Utf16(alias),
        ["type"] = "privateKey",
        ["m"] = key.M,
        ["d"] = Hex(key.PrivateKey),
        ["qx"] = Hex(key.PublicKey.AffineX.ToBigInteger()),
        ["qy"] = Hex(key.PublicKey.AffineY.ToBigInteger()),
        ["dke"] = Hex(key.Dke),
        ["chain"] = Array(chain.Select(o.FileOf)),
    };

    private static JsonObject Store(PkiOutput o, string file, string writer, string password, string? keyPassword, IEnumerable<JsonObject> entries,
        string about, string[] tests, IEnumerable<string>? expectedSigningChain = null, string? expectedError = null)
    {
        var json = new JsonObject
        {
            ["file"] = file,
            ["writer"] = writer,
            ["storePassword"] = password,
            ["keyPassword"] = keyPassword ?? password,
            ["about"] = about,
            ["entries"] = new JsonArray(entries.Select(e => (JsonNode)e).ToArray()),
        };
        if (expectedSigningChain is not null)
            json["expectedSigningChain"] = Array(expectedSigningChain);
        if (expectedError is not null)
            json["expectedError"] = expectedError;
        json["csharpTests"] = Array(tests);
        return json;
    }

    private static void CheckPackageReads(PkiOutput o, string file, string password, string alias, TestPki.TestKey key, int chainLength)
    {
        JksKeyStore store = JksKeyStore.Load(o.Read(file), password);
        JksPrivateKeyEntry entry = (JksPrivateKeyEntry)store.Entries.Single();
        Dstu4145PrivateKey read = entry.GetPrivateKey(password);
        Expect(entry.Alias == alias && read.D == key.PrivateKey && read.PublicKey.Q.Equals(key.PublicKey)
            && read.Dke!.AsSpan().SequenceEqual(key.Dke) && entry.Chain.Count == chainLength, $"the package reads {file}");
        Expect(SigningKey.FromJks(store, password).Certificate.Equals(entry.Chain[0]), $"SigningKey.FromJks({file})");
    }

    private static string Utf16(string s) => string.Concat(s.Select(c => ((int)c).ToString("x4")));

    private static void ExpectThrows<T>(Action action, string what) where T : Exception
    {
        try
        {
            action();
        }
        catch (T)
        {
            return;
        }
        throw new InvalidOperationException($"pki oracle self-check failed: expected {typeof(T).Name} ({what})");
    }

    private static readonly IEqualityComparer<byte[]> ByteArrays = EqualityComparer<byte[]>.Create(
        (a, b) => a.AsSpan().SequenceEqual(b), a => a.Length);

    private const string Readme = """
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
        """;
}
