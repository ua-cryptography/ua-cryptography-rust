using System.Xml;
using Org.BouncyCastle.Cms;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Asic;
using UA.Cryptography.Pki.Cades;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.Xades;
using UA.Cryptography.Pki.X509;
using static CSharpOracle.Generators.PkiOutput;
using static CSharpOracle.Generators.TspOcspFixtures;
using CadesOptions = UA.Cryptography.Pki.Cades.CadesOptions;
using Oids = UA.Cryptography.Tests.Support.Oids;
using PkiCmsBuilder = UA.Cryptography.Pki.Cms.CmsBuilder;
using PkiOids = UA.Cryptography.Pki.Oids;

namespace CSharpOracle.Generators;

/// <summary>package/: signatures made by the C# package itself, with the hierarchy's services wired in as the C# tests do.</summary>
internal static class PackageFixtures
{
    private static readonly byte[] Document = "Документ для підпису"u8.ToArray();
    private static readonly SignedFile File1 = new("заява.txt", "Текст заяви"u8.ToArray());
    private static readonly SignedFile File2 = new("data file.bin", [0, 1, 2, 3, 255]);
    private static readonly SignedFile[] AsicFiles = [new("contract.pdf", "%PDF-1.7 fake"u8.ToArray()), new("annex/табл.csv", "a;b\n1;2"u8.ToArray())];

    private static readonly (string, CheckStatus)[] LtRevocation =
        [("signer: revocation of 'Test Signer'", CheckStatus.Passed), ("signer: revocation of 'Test Issuing CA'", CheckStatus.Passed)];

    public static void Write(PkiOutput o)
    {
        Hierarchy pki = o.Pki;
        SigningKey signer = PkiLayer.Signer(pki);
        SignatureServices services = PkiLayer.Services(pki);
        var data = new Dictionary<string, string>
        {
            ["document"] = o.Write("package/data/document.txt", Document),
            [File1.Name] = o.Write("package/data/zayava.txt", File1.Content),
            [File2.Name] = o.Write("package/data/data-file.bin", File2.Content),
            [AsicFiles[0].Name] = o.Write("package/data/contract.pdf", AsicFiles[0].Content),
            [AsicFiles[1].Name] = o.Write("package/data/annex-tabl.csv", AsicFiles[1].Content),
        };

        // CadesSigner: hash × packaging × level; LT with a content time-stamp as PackageLevelsTAndLtAreReadByBouncyCastle.
        var cadesSigner = new CadesSigner(signer, services);
        foreach (string hashOid in new[] { Oids.Dstu7564_256, Oids.Gost34311 })
        foreach (bool detached in new[] { false, true })
        foreach (SignatureLevel level in new[] { SignatureLevel.B, SignatureLevel.T, SignatureLevel.LT })
        {
            bool contentTimeStamp = level == SignatureLevel.LT;
            byte[] signature = cadesSigner.Sign(Document, new CadesOptions(hashOid, detached, level, ContentTimeStamp: contentTimeStamp));
            CheckCadesWithBouncyCastle(o, signature, hashOid, detached);
            string file = o.Write($"package/cades-{Short(hashOid)}-{(detached ? "detached" : "enveloped")}-{level.ToString().ToLowerInvariant()}.p7s", signature);
            (string, CheckStatus)[] required = level == SignatureLevel.LT
                ? [("signer: trust", CheckStatus.Passed), ("signature time-stamp: imprint", CheckStatus.Passed), ("content time-stamp: imprint", CheckStatus.Passed),
                    ("certificate references", CheckStatus.Passed), ("revocation references", CheckStatus.Passed), .. LtRevocation]
                : [("signer: trust", CheckStatus.Passed)];
            o.AddSignature(new SignatureFixture(file, "CAdES", level == SignatureLevel.LT ? "X-Long" : level.ToString(), hashOid,
                detached ? "detached" : "enveloped", contentTimeStamp, "CadesSigner", [("content", data["document"])], [o.Trusting(true, required)],
                CadesTests(hashOid, detached, level)));
        }

        // ASiC-S of a detached GOST CAdES-T, as AsicContainerTests.PackageAsicSIsWellFormedAndVerifies.
        byte[] cades = cadesSigner.Sign(AsicFiles[0].Content, new CadesOptions(Oids.Gost34311, Detached: true, SignatureLevel.T));
        string asics = o.Write("package/asics-gost34311-t.asics", AsicContainer.CreateAsicS(AsicFiles[0].Name, AsicFiles[0].Content, cades));
        o.AddSignature(new SignatureFixture(asics, "ASiC-S", "T", Oids.Gost34311, "container", false, "AsicContainer.CreateAsicS",
            [(AsicFiles[0].Name, data[AsicFiles[0].Name])], [o.Trusting()], ["Pki/Asic/AsicContainerTests.PackageAsicSIsWellFormedAndVerifies"]));

        // XadesSigner: hash × level over two files (XadesSignerTests).
        var xadesSigner = new XadesSigner(signer, services);
        foreach (string hashOid in new[] { Oids.Dstu7564_256, Oids.Gost34311 })
        foreach (SignatureLevel level in new[] { SignatureLevel.B, SignatureLevel.T, SignatureLevel.LT })
        {
            string file = o.Write($"package/xades-{Short(hashOid)}-{level.ToString().ToLowerInvariant()}.xml",
                xadesSigner.SignToBytes([File1, File2], hashOid, level));
            o.AddSignature(new SignatureFixture(file, "XAdES", $"B-{level}", hashOid, "detached", false, "XadesSigner",
                [(File1.Name, data[File1.Name]), (File2.Name, data[File2.Name])],
                [o.Trusting(true, level == SignatureLevel.LT ? LtRevocation : [("signature", CheckStatus.Passed)])], XadesTests(hashOid, level)));
        }

        // ASiC-E: LT with services (PackageAsicEIsWellFormedAndVerifies) and B without (AddedOrReplacedEntriesAreCaught, WrongMimeTypeIsReported).
        (string, string)[] asicData = [(AsicFiles[0].Name, data[AsicFiles[0].Name]), (AsicFiles[1].Name, data[AsicFiles[1].Name])];
        XmlDocument lt = xadesSigner.Sign(AsicFiles, Oids.Dstu7564_256, SignatureLevel.LT);
        string asiceLt = o.Write("package/asice-dstu7564-lt.asice", AsicContainer.CreateAsicE(AsicFiles, lt));
        o.AddSignature(new SignatureFixture(asiceLt, "ASiC-E", "B-LT", Oids.Dstu7564_256, "container", false, "AsicContainer.CreateAsicE",
            asicData, [o.Trusting(true, [("manifest", CheckStatus.Passed), .. LtRevocation])], ["Pki/Asic/AsicContainerTests.PackageAsicEIsWellFormedAndVerifies"]));
        XmlDocument b = new XadesSigner(signer).Sign(AsicFiles);
        string asiceB = o.Write("package/asice-dstu7564-b.asice", AsicContainer.CreateAsicE(AsicFiles, b));
        o.AddSignature(new SignatureFixture(asiceB, "ASiC-E", "B-B", Oids.Dstu7564_256, "container", false, "AsicContainer.CreateAsicE",
            asicData, [o.Trusting()],
            ["Pki/Asic/AsicContainerTests.AddedOrReplacedEntriesAreCaught", "Pki/Asic/AsicContainerTests.WrongMimeTypeIsReported"]));

        WriteTwin(o, signer, data["document"]);
        WriteMissingTsaCertificate(o, data["document"]);
        o.WriteText("package/README.md", Readme);
    }

    /// <summary>CadesSignerTests.ForeignCertificateFailsTheSigningCertificateCheck: honest with the twin, swapped for the real certificate.</summary>
    private static void WriteTwin(PkiOutput o, SigningKey signer, string document)
    {
        Certificate twin = o.LoadCertificate(HierarchyFixtures.Twin);
        var twinSigner = new SigningKey(signer.Key, [twin, .. signer.Chain.Skip(1)]);
        byte[] attributes = PkiCmsBuilder.SignedAttributes(Document, PkiOids.Data, twinSigner, Oids.Dstu7564_256);
        byte[] signerInfo = PkiCmsBuilder.SignerInfo(attributes, twinSigner, Oids.Dstu7564_256).SignerInfo;
        string honest = o.Write("package/twin-honest.p7s", PkiCmsBuilder.SignedData(signerInfo, Oids.Dstu7564_256, PkiOids.Data, Document, [twin]));
        string swapped = o.Write("package/twin-swapped.p7s", PkiCmsBuilder.SignedData(signerInfo, Oids.Dstu7564_256, PkiOids.Data, Document, [signer.Certificate]));
        string[] tests = ["Pki/Cades/CadesSignerTests.ForeignCertificateFailsTheSigningCertificateCheck"];
        o.AddSignature(new SignatureFixture(honest, "CAdES", "B", Oids.Dstu7564_256, "enveloped", false, "UA.Cryptography.Pki.Cms.CmsBuilder (twin certificate)",
            [("content", document)], [o.Trusting()], tests));
        o.AddSignature(new SignatureFixture(swapped, "CAdES", "B", Oids.Dstu7564_256, "enveloped", false,
            "UA.Cryptography.Pki.Cms.CmsBuilder (signed for the twin, carries signer.cer)",
            [("content", document)], [o.Trusting(false, ("CMS: signing certificate", CheckStatus.Failed))], tests));
    }

    /// <summary>
    /// CadesSignerTests.TimeStampWithoutTheServiceCertificateIsCompletedFromCaIssuers: CAdES-T with only the signer's
    /// certificate (which names a caIssuers bundle) and a token without the TSA's certificate.
    /// </summary>
    private static void WriteMissingTsaCertificate(PkiOutput o, string document)
    {
        Hierarchy pki = o.Pki;
        const string bundleUrl = "http://ca.test/bundle.p7b";
        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        var key = pki.Signer.Key.ToPki();
        Certificate certificate = new CertificateBuilder(pki.Signer.Certificate.ToPki().Subject, key.PublicKey)
            .AddKeyUsage(KeyUsageFlags.DigitalSignature | KeyUsageFlags.NonRepudiation)
            .AddAuthorityInfoAccess(null, bundleUrl)
            .Issue(ca, pki.IssuingCa.Key.ToPki());
        string certificateFile = o.WriteCertificate("package/caissuers-signer.cer", certificate.Encoded);
        var services = new SignatureServices { TimeStamps = new PkiLayer.TimeStamps(pki, includeCertificate: false) };
        byte[] signature = new CadesSigner(new SigningKey(key, [certificate]), services).Sign(Document, new CadesOptions(Level: SignatureLevel.T));
        string file = o.Write("package/cades-t-no-tsa-certificate.p7s", signature);
        string[] tests = ["Pki/Cades/CadesSignerTests.TimeStampWithoutTheServiceCertificateIsCompletedFromCaIssuers"];
        o.AddSignature(new SignatureFixture(file, "CAdES", "T", Oids.Dstu7564_256, "enveloped", false, $"CadesSigner ({certificateFile}, TSA without certificate)",
            [("content", document)],
            [
                new([], [], true) { Required = [("signature time-stamp: service certificate", CheckStatus.Warning)] },
                new([o.RootFile], [], true)
                {
                    Downloads = new() { [bundleUrl] = [o.FileOf(pki.IssuingCa.Certificate), o.FileOf(pki.Tsa.Identity.Certificate)] },
                    Required = [("signature time-stamp: signature", CheckStatus.Passed), ("signer: trust", CheckStatus.Passed)],
                },
            ],
            tests));
    }

    private static string[] CadesTests(string hashOid, bool detached, SignatureLevel level) => level switch
    {
        SignatureLevel.B => ["Pki/Cades/CadesSignerTests.PackageSignatureVerifiesByThePackage", "Pki/Cades/CadesSignerTests.PackageSignatureVerifiesByTheBouncyCastleRecipe",
            .. (hashOid == Oids.Dstu7564_256 ? (string[])["Pki/Cades/CadesSignerTests.TamperedDataFailsTheMessageDigest / TamperedSignatureValueFails / SigningCertificateV2NamesTheIssuerAndSerialNumber / DetachedSignatureWithoutDataAndUntrustedRootFail"] : [])],
        SignatureLevel.T => ["Pki/Tsp/TimeStampTokenTests.SignatureTimeStampOverOtherBytesFailsTheSignature (the valid half)"],
        _ => detached ? ["(LT, detached: completes the grid)"] : ["Pki/Cades/CadesSignerTests.PackageLevelsTAndLtAreReadByBouncyCastle"],
    };

    private static string[] XadesTests(string hashOid, SignatureLevel level)
    {
        var tests = new List<string>();
        if (level == SignatureLevel.B)
            tests.Add("Pki/Xades/XadesSignerTests.PackageSignatureVerifiesWithMicrosoftCanonicalization");
        if (hashOid == Oids.Dstu7564_256 || level == SignatureLevel.LT)
            tests.Add("Pki/Xades/XadesSignerTests.PackageSignatureVerifiesByThePackage");
        if (hashOid == Oids.Dstu7564_256 && level == SignatureLevel.B)
            tests.Add("Pki/Xades/XadesSignerTests.TamperedFileFailsItsReference / ChangedSignedPropertyOrSignatureValueFails / DuplicateIdIsRejected / MissingFileIsReported");
        if (tests.Count == 0)
            tests.Add("(completes the hash × level grid)");
        return [.. tests];
    }

    private static void CheckCadesWithBouncyCastle(PkiOutput o, byte[] signature, string hashOid, bool detached)
    {
        var cms = new CmsSignedData(signature);
        SignerInformation info = cms.GetSignerInfos().GetSigners().Single();
        Expect(info.DigestAlgorithmID.Algorithm.Id == hashOid && UaPki.SignatureAlgorithmFor(hashOid) == info.SignatureAlgorithm.Algorithm.Id, "algorithms");
        Expect(detached == (cms.SignedContent is null), "packaging");
        Expect(UaPki.MessageDigest(info).SequenceEqual(UaPki.Hash(hashOid, Document)), "messageDigest (BouncyCastle recipe)");
        Expect(UaPki.VerifyCmsSigner(info, o.Pki.Signer.Certificate) && info.GetSignature().Length == 64, "signer (BouncyCastle recipe)");
    }

    private const string Readme = """
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
        """;
}
