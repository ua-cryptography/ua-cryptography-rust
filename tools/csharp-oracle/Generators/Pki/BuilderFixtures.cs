using System.Text;
using System.Text.Json.Nodes;
using System.Xml;
using Org.BouncyCastle.Cms;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.Xml;
using static CSharpOracle.Generators.PkiOutput;
using static CSharpOracle.Generators.TspOcspFixtures;
using SupportCadesOptions = UA.Cryptography.Tests.Support.CadesOptions;

namespace CSharpOracle.Generators;

/// <summary>cades/ and xades/: every variant of the test builders CadesBuilder and XadesBuilder.</summary>
internal static class BuilderFixtures
{
    private static readonly byte[] Data = "test"u8.ToArray();
    private const string DataName = "data.txt";

    public static void Write(PkiOutput o)
    {
        WriteCades(o);
        WriteXades(o);
    }

    // ---- cades/ --------------------------------------------------------------------------------------------------

    private static void WriteCades(PkiOutput o)
    {
        string dataFile = o.Write("cades/data.txt", Data);
        foreach (string hashOid in new[] { Oids.Dstu7564_256, Oids.Gost34311 })
        foreach (bool enveloped in new[] { true, false })
        foreach (CadesLevel level in new[] { CadesLevel.B, CadesLevel.T, CadesLevel.XLong })
        foreach (bool contentTimeStamp in new[] { false, true })
        {
            byte[] signature = CadesBuilder.Build(Data, o.Pki, new SupportCadesOptions(hashOid, enveloped, level, contentTimeStamp));
            CheckCadesWithBouncyCastle(o, signature, hashOid, enveloped);
            string name = $"cades-{Short(hashOid)}-{(enveloped ? "enveloped" : "detached")}-{LevelName(level).ToLowerInvariant()}{(contentTimeStamp ? "-content-ts" : "")}";
            string file = o.Write($"cades/{name}.p7s", signature);
            o.AddSignature(new SignatureFixture(file, "CAdES", LevelName(level), hashOid, enveloped ? "enveloped" : "detached", contentTimeStamp,
                "CadesBuilder", [(DataName, dataFile)], [o.Trusting(true, CadesRequired(level, contentTimeStamp))],
                CadesTests(hashOid, enveloped, level, contentTimeStamp)));

            // ASiC-S around the detached variants the C# tests wrap.
            bool wrapped = !enveloped && ((hashOid == Oids.Gost34311 && level == CadesLevel.T && contentTimeStamp)
                || (hashOid == Oids.Dstu7564_256 && level == CadesLevel.XLong && !contentTimeStamp));
            if (!wrapped)
                continue;
            string asics = o.Write($"cades/asics-{Short(hashOid)}-{LevelName(level).ToLowerInvariant()}{(contentTimeStamp ? "-content-ts" : "")}.asics",
                CadesBuilder.WrapAsicS(DataName, Data, signature));
            o.AddSignature(new SignatureFixture(asics, "ASiC-S", LevelName(level), hashOid, "container", contentTimeStamp,
                "CadesBuilder.WrapAsicS", [(DataName, dataFile)], [o.Trusting(true, CadesRequired(level, contentTimeStamp))],
                contentTimeStamp
                    ? ["Signatures/CadesTests.AsicSContainerIsWellFormedAndVerifies", "Pki/Asic/AsicContainerTests.TestBuilderContainersVerify"]
                    : ["Pki/Asic/AsicContainerTests.TestBuilderContainersVerify (another level)"]));
        }
        o.WriteText("cades/README.md", CadesReadme);
    }

    private static string LevelName(CadesLevel level) => level == CadesLevel.XLong ? "X-Long" : level.ToString();

    private static (string, CheckStatus)[] CadesRequired(CadesLevel level, bool contentTimeStamp)
    {
        var required = new List<(string, CheckStatus)> { ("CMS: signature", CheckStatus.Passed), ("signer: trust", CheckStatus.Passed) };
        if (level >= CadesLevel.T)
            required.Add(("signature time-stamp: imprint", CheckStatus.Passed));
        if (contentTimeStamp)
            required.Add(("content time-stamp: imprint", CheckStatus.Passed));
        if (level == CadesLevel.XLong)
        {
            required.Add(("certificate references", CheckStatus.Passed));
            required.Add(("revocation references", CheckStatus.Passed));
            required.Add(("signer: revocation of 'Test Signer'", CheckStatus.Passed));
            required.Add(("signer: revocation of 'Test Issuing CA'", CheckStatus.Passed));
        }
        else
        {
            required.Add(("signer: revocation of 'Test Signer'", CheckStatus.Warning));
        }
        return [.. required];
    }

    private static string[] CadesTests(string hashOid, bool enveloped, CadesLevel level, bool contentTimeStamp)
    {
        bool dstu = hashOid == Oids.Dstu7564_256;
        var tests = new List<string>();
        (bool, bool, CadesLevel, bool)[] builderRows =
        [
            (true, true, CadesLevel.B, false), (true, false, CadesLevel.T, true), (false, true, CadesLevel.T, false),
            (true, true, CadesLevel.XLong, false), (false, false, CadesLevel.XLong, true),
        ];
        if (builderRows.Contains((dstu, enveloped, level, contentTimeStamp)))
            tests.Add("Pki/Cades/CadesSignerTests.TestBuilderSignatureVerifiesByThePackage");
        if (level == CadesLevel.B && !contentTimeStamp)
            tests.Add("Signatures/CadesTests.SignatureVerifies");
        if (dstu && enveloped && level == CadesLevel.B && !contentTimeStamp)
        {
            tests.Add("Signatures/CadesTests.SignerCertificateChainsToTheRoot");
            tests.Add("Signatures/CadesTests.TamperedDataFailsMessageDigest");
            tests.Add("Signatures/CadesTests.ForeignCertificateFailsSigningCertificateCheck");
        }
        if (enveloped && level == CadesLevel.T && contentTimeStamp)
            tests.Add("Signatures/CadesTests.TimeStampsCoverDataAndSignature");
        if (dstu && enveloped && level == CadesLevel.XLong && !contentTimeStamp)
            tests.Add("Signatures/CadesTests.LongTermValidationDataIsConsistent");
        if (!dstu && !enveloped && level == CadesLevel.T && contentTimeStamp)
            tests.Add("Signatures/CadesTests.AsicSContainerIsWellFormedAndVerifies (the .p7s inside)");
        if (tests.Count == 0)
            tests.Add("(completes the hash × packaging × level × content time-stamp grid)");
        return [.. tests];
    }

    /// <summary>The recipe of Signatures/CadesTests: BouncyCastle splits the CMS, the library verifies.</summary>
    private static void CheckCadesWithBouncyCastle(PkiOutput o, byte[] signature, string hashOid, bool enveloped)
    {
        var cms = new CmsSignedData(signature);
        SignerInformation signer = cms.GetSignerInfos().GetSigners().Single();
        Expect(signer.DigestAlgorithmID.Algorithm.Id == hashOid, "digest algorithm");
        Expect(UaPki.MessageDigest(signer).SequenceEqual(UaPki.Hash(hashOid, Data)), "messageDigest");
        Expect(UaPki.VerifyCmsSigner(signer, o.Pki.Signer.Certificate), "CMS signer verifies (UaPki)");
        Expect(enveloped == (cms.SignedContent is not null), "packaging");
    }

    // ---- xades/ --------------------------------------------------------------------------------------------------

    private static void WriteXades(PkiOutput o)
    {
        string dataFile = o.Write("xades/data.txt", Data);
        foreach (string hashOid in new[] { Oids.Dstu7564_256, Oids.Gost34311 })
        foreach (XadesLevel level in new[] { XadesLevel.B, XadesLevel.T, XadesLevel.LT })
        {
            XmlDocument signature = XadesBuilder.Build(Data, DataName, o.Pki, hashOid, level);
            string name = $"{Short(hashOid)}-{level.ToString().ToLowerInvariant()}";
            var required = new List<(string, CheckStatus)> { ("signature", CheckStatus.Passed), ("signer: trust", CheckStatus.Passed) };
            if (level >= XadesLevel.T)
                required.Add(("signature time-stamp: imprint", CheckStatus.Passed));
            if (level == XadesLevel.LT)
            {
                required.Add(("signer: revocation of 'Test Signer'", CheckStatus.Passed));
                required.Add(("signer: revocation of 'Test Issuing CA'", CheckStatus.Passed));
            }

            string xml = o.Write($"xades/xades-{name}.xml", Encoding.UTF8.GetBytes(signature.OuterXml));
            o.AddSignature(new SignatureFixture(xml, "XAdES", $"B-{level}", hashOid, "detached", false, "XadesBuilder",
                [(DataName, dataFile)], [o.Trusting(true, [.. required])], XadesTests(hashOid, level, asicE: false)));

            string asice = o.Write($"xades/asice-{name}.asice", XadesBuilder.WrapAsicE(DataName, Data, signature));
            o.AddSignature(new SignatureFixture(asice, "ASiC-E", $"B-{level}", hashOid, "container", false, "XadesBuilder.WrapAsicE",
                [(DataName, dataFile)], [o.Trusting(true, [.. required])], XadesTests(hashOid, level, asicE: true)));

            if (hashOid == Oids.Dstu7564_256 && level == XadesLevel.LT)
                WriteCanonicalForms(o, xml);
        }
        o.WriteText("xades/README.md", XadesReadme);
    }

    private static string[] XadesTests(string hashOid, XadesLevel level, bool asicE)
    {
        bool dstu = hashOid == Oids.Dstu7564_256;
        var tests = new List<string>();
        if (!asicE && ((dstu && level == XadesLevel.B) || (!dstu && level == XadesLevel.T) || (dstu && level == XadesLevel.LT)))
            tests.Add("Pki/Xades/XadesSignerTests.TestBuilderSignatureVerifiesByThePackage");
        if (level == XadesLevel.LT && (!asicE || dstu))
            tests.Add("Signatures/XadesTests.SignatureVerifies");
        if (!asicE && dstu && level == XadesLevel.B)
            tests.Add("Signatures/XadesTests.TamperedDataBreaksTheReference");
        if (!asicE && dstu && level == XadesLevel.LT)
        {
            tests.Add("Signatures/XadesTests.SignerCertificateIsIssuedByEmbeddedCa");
            tests.Add("Signatures/XadesTests.RevocationValuesAreSignedAndGood");
            tests.Add("Pki/Xml/XmlCanonicalizerTests.XadesBuilderDocumentMatchesMicrosoft (with c14n-xades-dstu7564-lt.json)");
        }
        if (!asicE && level == XadesLevel.T)
            tests.Add("Signatures/XadesTests.TimeStampCoversTheSignature");
        if (asicE && dstu && level == XadesLevel.LT)
            tests.Add("Pki/Asic/AsicContainerTests.TestBuilderContainersVerify");
        if (tests.Count == 0)
            tests.Add("(completes the hash × level × packaging grid)");
        return [.. tests];
    }

    /// <summary>
    /// XmlCanonicalizerTests.XadesBuilderDocumentMatchesMicrosoft: Microsoft's exclusive C14N of every element (as
    /// XadesBuilder.Canonicalize does it) and inclusive C14N of the whole document.
    /// </summary>
    private static void WriteCanonicalForms(PkiOutput o, string xmlFile)
    {
        XmlDocument document = XmlSafe.Load(o.Read(xmlFile));
        var elements = new JsonArray();
        int index = 0;
        foreach (XmlElement element in document.GetElementsByTagName("*").Cast<XmlElement>())
        {
            byte[] canonical = XadesBuilder.Canonicalize(element);
            Expect(canonical.AsSpan().SequenceEqual(XmlCanonicalizer.Canonicalize(element, XmlCanonicalizer.ExclusiveC14N)), "package exc-c14n");
            elements.Add(new JsonObject
            {
                ["index"] = index++,
                ["namespace"] = element.NamespaceURI,
                ["localName"] = element.LocalName,
                ["excC14n"] = Encoding.UTF8.GetString(canonical),
            });
        }

        var transform = new System.Security.Cryptography.Xml.XmlDsigC14NTransform(false);
        transform.LoadInput(XmlSafe.Load(o.Read(xmlFile)));
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        Expect(buffer.ToArray().AsSpan().SequenceEqual(XmlCanonicalizer.Canonicalize(XmlSafe.Load(o.Read(xmlFile)), XmlCanonicalizer.InclusiveC14N)),
            "package inclusive c14n");

        o.WriteJson("xades/c14n-xades-dstu7564-lt.json", new JsonObject
        {
            ["document"] = xmlFile,
            ["about"] = "elements in document order (GetElementsByTagName(\"*\")); excC14n is Microsoft's XmlDsigExcC14NTransform of the element re-parsed from its OuterXml (XadesBuilder.Canonicalize); inclusiveC14n is XmlDsigC14NTransform of the whole document",
            ["elements"] = elements,
            ["inclusiveC14n"] = Encoding.UTF8.GetString(buffer.ToArray()),
        });
    }

    private const string CadesReadme = """
        # cades/

        CAdES signatures made by the C# test builder `Support/CadesBuilder.cs` (BouncyCastle ASN.1, the library's DSTU 4145)
        with the `hierarchy/` signer over `data.txt` (`"test"`), recorded by `tools/csharp-oracle -- pki`. Every file is
        listed in `../manifest.json` (format, level, hash, packaging, data, the C# package's verdict and checks, the C#
        tests it stands in for) and was verified by the C# package's `SignatureVerifier` before it was kept.

        | Files | What |
        |-------|------|
        | `cades-{dstu7564,gost34311}-{enveloped,detached}-{b,t,x-long}[-content-ts].p7s` | the full grid of `CadesBuilder.Build(data, Hierarchy.Shared, new CadesOptions(hash, enveloped, level, contentTimeStamp))`: hash DSTU 7564-256 or GOST 34.311 (signature DSTU 4145 with the same hash), data inside or detached, level B / T (signatureTimeStampToken) / X-Long (complete certificate and revocation references + values: CA and root certificates, "good" OCSP for signer and CA), with or without a contentTimeStamp signed attribute; signingTime always present |
        | `asics-gost34311-t-content-ts.asics` | `CadesBuilder.WrapAsicS("data.txt", data, …)` around the detached GOST T + content time-stamp signature (the exact variant of the C# tests) |
        | `asics-dstu7564-x-long.asics` | the same around the detached DSTU 7564 X-Long signature |
        | `data.txt` | the signed data |

        Verification used for the verdict: trust anchor `hierarchy/root.cer`, extra certificates = every hierarchy
        certificate (`PkiLayer.AllCertificates`), offline. Levels below X-Long report the revocation of the signer as a
        warning (no OCSP data); the verdict is still valid.

        Stands in for: `Pki/Cades/CadesSignerTests.TestBuilderSignatureVerifiesByThePackage` (its five rows are among the
        files), `Signatures/CadesTests` (all tests: the BouncyCastle recipe becomes a Rust recipe over these files),
        `Pki/Asic/AsicContainerTests.TestBuilderContainersVerify` (ASiC-S half). Tampering (data, signature value, foreign
        certificate) is done by the Rust tests on these files; the twin-certificate case is in `package/`.
        """;

    private const string XadesReadme = """
        # xades/

        XAdES signatures made by the C# test builder `Support/XadesBuilder.cs` (System.Xml + Microsoft's exclusive C14N, the
        library's hashes and DSTU 4145) with the `hierarchy/` signer over `data.txt` (`"test"`, reference URI `data.txt`),
        recorded by `tools/csharp-oracle -- pki`. Every signature file is listed in `../manifest.json` and was verified by
        the C# package's `SignatureVerifier` before it was kept.

        | Files | What |
        |-------|------|
        | `xades-{dstu7564,gost34311}-{b,t,lt}.xml` | `XadesBuilder.Build(data, "data.txt", Hierarchy.Shared, hash, level).OuterXml` as UTF-8 (no XML declaration), a detached signature next to `data.txt`; level B (signed properties), T (+ SignatureTimeStamp over the canonical ds:SignatureValue), LT (+ CertificateValues: every hierarchy certificate except the signer's, + RevocationValues: "good" OCSP for signer and CA) |
        | `asice-{dstu7564,gost34311}-{b,t,lt}.asice` | `XadesBuilder.WrapAsicE("data.txt", data, signature)`: mimetype, data.txt, META-INF/manifest.xml, META-INF/signatures001.xml |
        | `c14n-xades-dstu7564-lt.json` | for `xades-dstu7564-lt.xml`: Microsoft's exclusive C14N of every element in document order (`XadesBuilder.Canonicalize`) and its inclusive C14N of the whole document |
        | `data.txt` | the signed data |

        Verification used for the verdict: trust anchor `hierarchy/root.cer`, extra certificates = every hierarchy
        certificate, offline; the detached data is resolved by the reference URI `data.txt`.

        Stands in for: `Pki/Xades/XadesSignerTests.TestBuilderSignatureVerifiesByThePackage` (its three rows),
        `Signatures/XadesTests` (all tests, both packagings), `Pki/Asic/AsicContainerTests.TestBuilderContainersVerify`
        (ASiC-E half), `Pki/Xml/XmlCanonicalizerTests.XadesBuilderDocumentMatchesMicrosoft` (the JSON).
        """;
}
