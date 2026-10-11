using System.Text.Json.Nodes;
using UA.Cryptography.Pki.KeyStore;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;
using static CSharpOracle.Generators.PkiOutput;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace CSharpOracle.Generators;

/// <summary>
/// providers/: the PrivatBank .sig and the "Дія" ASiC-E as the providers make them (ProviderProfiles), and as the C#
/// command-line tool ua-sign makes them, each checked against the provider's profile.
/// </summary>
internal static class ProviderFixtures
{
    /// <summary>Fixed service addresses in the bank customer's certificate, so a Rust test can serve them.</summary>
    public const string OcspUrl = "http://127.0.0.1:18089/ocsp";

    public const string CaIssuersUrl = "http://127.0.0.1:18089/ca.p7b";

    public const string Password = "provider formats";

    private static readonly byte[] Document = "Документ для підпису\n"u8.ToArray();

    public static void Write(PkiOutput o)
    {
        Hierarchy pki = o.Pki;
        string document = o.Write("providers/doc.txt", Document);
        string root = o.RootFile;
        string ca = o.FileOf(pki.IssuingCa.Certificate);
        string tsa = o.FileOf(pki.Tsa.Identity.Certificate);
        string ocsp = o.FileOf(pki.IssuingCaOcsp.Identity.Certificate);

        // ---- PrivatBank ----------------------------------------------------------------------------------------
        TestPki.TestIdentity customer = TestPki.Issue("CN=Test Bank Customer,O=UA Cryptography Tests,C=UA", pki.Signer.Key, pki.IssuingCa,
            signatureAlgorithm: Oids.Dstu4145WithDstu7564, ocspUrl: OcspUrl, caIssuersUrl: CaIssuersUrl);
        string customerFile = o.WriteCertificate("providers/privatbank/customer.cer", customer.Certificate.GetEncoded());
        TestPki.TestIdentity agreement = TestPki.Issue("CN=Test Bank Customer,O=UA Cryptography Tests,C=UA", TestPki.GenerateKey(431),
            pki.IssuingCa, signatureAlgorithm: Oids.Dstu4145WithDstu7564);
        string agreementFile = o.WriteCertificate("providers/privatbank/agreement.cer", agreement.Certificate.GetEncoded());
        string customerOcsp = o.Write("providers/privatbank/customer-ocsp.der",
            OcspResponder.Encode(pki.IssuingCaOcsp.Respond(customer.Certificate, pki.IssuingCa.Certificate)));

        using var server = new LocalPkiServer(pki);
        server.ExtraCertificates.Add(customer.Certificate);
        byte[] bundle;
        using (var http = new HttpClient())
            bundle = http.GetByteArrayAsync(server.CaIssuersUrl).GetAwaiter().GetResult();
        string bundleFile = o.Write("providers/privatbank/ca.p7b", bundle);
        Expect(server.CaIssuersRequests == 1, "the caIssuers bundle came from LocalPkiServer");

        string bankSig = o.Write("providers/privatbank/doc.txt.sig", PrivatBankSig.Build(Document, pki, customer));
        PrivatBankSig.AssertProfile(o.Read(bankSig), Document, customer.Certificate);
        var online = new Verification([root], [], true)
        {
            Downloads = new() { [CaIssuersUrl] = [ca, tsa, ocsp] },
            OnlineOcsp = new() { [customerFile] = customerOcsp, [ca] = HierarchyFixtures.IssuingCaOcsp },
            Required =
            [
                ("signature time-stamp: signature", CheckStatus.Passed), ("signer: trust", CheckStatus.Passed),
                ("signer: revocation of 'Test Bank Customer'", CheckStatus.Passed),
            ],
        };
        o.AddSignature(new SignatureFixture(bankSig, "CAdES", "T", Oids.Dstu7564_256, "enveloped", false, "PrivatBankSig.Build",
            [("doc.txt", document)],
            [
                new([], [], true) { Required = [("signature time-stamp: service certificate", CheckStatus.Warning)] },
                new([root], [], false) { Required = [("signer: trust", CheckStatus.Failed)] },
                online,
                new([root], [ca, tsa], true) { Required = [("signature time-stamp: signature", CheckStatus.Passed), ("signer: trust", CheckStatus.Passed)] },
            ],
            ["Signatures/ProviderFormatTests.PrivatBankSigAsTheBankMakesItVerifies"]));

        // The key store as the bank issues it (root first, then the key-agreement certificate), and ua-sign's .sig.
        var store = new JksKeyStore();
        store.AddPrivateKey("pb_sign", customer.Key.ToPki(),
            new[] { pki.Root.Certificate, pki.IssuingCa.Certificate, customer.Certificate, agreement.Certificate }.Select(c => c.ToPki()).ToList(),
            Password);
        string keyStore = o.Write("providers/privatbank/key.jks", store.Save(Password));
        string uaSignSig = UaSign(o, keyStore, "providers/privatbank/doc.txt.ua-sign.sig",
            ["--format", "cades", "--level", "T", "--tsa", server.TsaUrl]);
        PrivatBankSig.AssertProfile(o.Read(uaSignSig), Document, customer.Certificate);
        o.AddSignature(new SignatureFixture(uaSignSig, "CAdES", "T", Oids.Dstu7564_256, "enveloped", false, "ua-sign (C# CLI)",
            [("doc.txt", document)],
            [online, new([root], [ca], true) { Required = [("signature time-stamp: signature", CheckStatus.Passed), ("signer: trust", CheckStatus.Passed)] }],
            ["Signatures/ProviderFormatTests.PrivatBankSigIsMadeByUaSignAndVerifies (bank-issued)"]));

        // ---- "Дія" ---------------------------------------------------------------------------------------------
        string diia = o.Write("providers/diia/doc.txt.asice", DiiaAsicE.Build(Document, "doc.txt", pki));
        DiiaAsicE.AssertProfile(o.Read(diia), "doc.txt", Document, pki.Signer.Certificate, pki.IssuingCa.Certificate, ocspFor: pki.Signer.Certificate);
        o.AddSignature(new SignatureFixture(diia, "ASiC-E", "B-LT", Oids.Dstu7564_256, "container", false, "DiiaAsicE.Build",
            [("doc.txt", document)],
            [new([root], [], true)
            {
                Required =
                [
                    ("manifest", CheckStatus.Passed), ("signature time-stamp: signature", CheckStatus.Passed),
                    ("signer: revocation of 'Test Signer'", CheckStatus.Passed), ("signer: revocation of 'Test Issuing CA'", CheckStatus.Warning),
                ],
            }],
            ["Signatures/ProviderFormatTests.DiiaAsicEAsDiiaMakesItVerifies"]));

        var diiaStore = new JksKeyStore();
        diiaStore.AddPrivateKey("signer", pki.Signer.Key.ToPki(), pki.SignerChain.Select(c => c.ToPki()).ToList(), Password);
        string diiaKeyStore = o.Write("providers/diia/key.jks", diiaStore.Save(Password));
        string uaSignAsice = UaSign(o, diiaKeyStore, "providers/diia/doc.txt.ua-sign.asice",
            ["--format", "asic-e", "--level", "LT", "--tsa", server.TsaUrl, "--ocsp", server.OcspUrl]);
        DiiaAsicE.AssertProfile(o.Read(uaSignAsice), "doc.txt", Document, pki.Signer.Certificate, pki.IssuingCa.Certificate,
            ocspFor: pki.Signer.Certificate);
        o.AddSignature(new SignatureFixture(uaSignAsice, "ASiC-E", "B-LT", Oids.Dstu7564_256, "container", false, "ua-sign (C# CLI)",
            [("doc.txt", document)],
            [new([root], [], true)
            {
                Required = [("signer: revocation of 'Test Signer'", CheckStatus.Passed), ("signer: revocation of 'Test Issuing CA'", CheckStatus.Passed)],
            }],
            ["Signatures/ProviderFormatTests.DiiaAsicEIsMadeByUaSignAndVerifies"]));

        o.WriteJson("providers/providers.json", new JsonObject
        {
            ["document"] = document,
            ["keyStorePassword"] = Password,
            ["privatbank"] = new JsonObject
            {
                ["customer"] = customerFile,
                ["customerKey"] = "the signer's key: hierarchy/keys.json identities.signer.key",
                ["agreementCertificate"] = agreementFile,
                ["ocspUrl"] = OcspUrl,
                ["caIssuersUrl"] = CaIssuersUrl,
                ["caIssuersBundle"] = bundleFile,
                ["caIssuersBundleCertificates"] = Array(new[] { ca, tsa, ocsp }),
                ["customerOcsp"] = customerOcsp,
                ["keyStore"] = keyStore,
                ["keyStoreAlias"] = "pb_sign",
                ["keyStoreChain"] = Array(new[] { root, ca, customerFile, agreementFile }),
            },
            ["diia"] = new JsonObject
            {
                ["signer"] = o.FileOf(pki.Signer.Certificate),
                ["keyStore"] = diiaKeyStore,
                ["keyStoreAlias"] = "signer",
                ["keyStoreChain"] = Array(pki.SignerChain.Select(o.FileOf)),
            },
        });
        o.WriteText("providers/README.md", Readme);
    }

    /// <summary>Runs the C# ua-sign over doc.txt with a key store and returns the output file.</summary>
    private static string UaSign(PkiOutput o, string keyStore, string output, string[] options)
    {
        string input = Path.Combine(o.Directory, "providers", "doc.txt");
        var text = new StringWriter();
        int code = UA.Cryptography.Cli.UaSign.Run(
            ["sign", "--keystore", Path.Combine(o.Directory, keyStore), "--password", Password, "--in", input,
                "--out", Path.Combine(o.Directory, output), .. options],
            text, text);
        Expect(code == UA.Cryptography.Cli.UaSign.Valid, $"ua-sign sign {string.Join(' ', options)}: {text}");
        return output;
    }

    private const string Readme = $"""
        # providers/

        The two provider formats of docs/provider-formats.md (C# repository), recorded by `tools/csharp-oracle -- pki` with
        the `hierarchy/` PKI. "As the provider makes it" comes from `Support/ProviderProfiles.cs` (BouncyCastle CMS /
        System.Xml); "by ua-sign" is the output of the C# command-line tool (`UaSign.Run sign …`) with a JKS key and
        `LocalPkiServer` as TSA / OCSP. Every signature was checked against the provider's profile
        (`PrivatBankSig.AssertProfile`, `DiiaAsicE.AssertProfile`) and verified by the C# package; the verifications and
        verdicts are in `../manifest.json`. Paths, URLs and passwords are in `providers.json`.

        | File | What |
        |------|------|
        | `doc.txt` | the signed document, `"Документ для підпису\n"` |
        | `privatbank/customer.cer` | "Test Bank Customer": the signer's key re-certified by the issuing CA with authorityInfoAccess OCSP `{OcspUrl}` and caIssuers `{CaIssuersUrl}` (fixed addresses: a Rust test either serves them on that port or answers through injected services) |
        | `privatbank/agreement.cer` | the customer's key-agreement certificate (m = 431), as the bank puts it into the key store |
        | `privatbank/ca.p7b` | the caIssuers bundle `LocalPkiServer` serves: certs-only CMS with issuing CA, TSA and OCSP responder |
        | `privatbank/customer-ocsp.der` | "good" OCSP about the customer from `hierarchy/ocsp.cer` (what LocalPkiServer answers) |
        | `privatbank/doc.txt.sig` | `PrivatBankSig.Build`: enveloped CAdES-T, DSTU 7564; signingTime (UTCTime), signingCertificateV2 with issuerSerial; the signature time-stamp without the TSA certificate; only the customer certificate inside |
        | `privatbank/key.jks` | the key store as the bank issues it (alias `pb_sign`, chain root, CA, customer, agreement; password `{Password}`), written by the C# package |
        | `privatbank/doc.txt.ua-sign.sig` | `ua-sign sign --format cades --level T` with that key store |
        | `diia/doc.txt.asice` | `DiiaAsicE.Build`: ASiC-E with XAdES-B-LT as "Дія" makes it (ids `id-…`, `xades-id-…`, `TS-…`, empty Type on the data reference, namespaces declared on the root, CertificateValues CA + root + OCSP responder, one OCSP response about the signer with a zero issuerKeyHash) |
        | `diia/key.jks` | the hierarchy signer with its chain (alias `signer`, password `{Password}`), written by the C# package |
        | `diia/doc.txt.ua-sign.asice` | `ua-sign sign --format asic-e --level LT` with that key store |

        The manifest's verifications mirror the C# test: the bank's `.sig` is valid offline with no options (time-stamp
        service certificate: warning), invalid with only the root (`signer: trust` fails: the CA is missing), valid
        "online" — `downloads` maps the caIssuers URL to the bundle's certificates and `onlineOcsp` maps certificates to
        recorded responses — and valid with the root plus the CA and TSA certificates.

        Stands in for `Signatures/ProviderFormatTests` (all four tests; the Rust CLI tests run their own ua-sign and check
        its output against the profiles with Rust recipes, and verify these files to cover the providers' own output).
        """;
}
