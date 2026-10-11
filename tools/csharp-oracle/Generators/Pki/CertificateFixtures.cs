using System.Text.Json.Nodes;
using Org.BouncyCastle.Asn1.X509;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Pki.X509;
using static CSharpOracle.Generators.PkiOutput;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;
using Oids = UA.Cryptography.Tests.Support.Oids;
using PkiOids = UA.Cryptography.Pki.Oids;

namespace CSharpOracle.Generators;

/// <summary>
/// certificates/: BouncyCastle's reading of every real certificate in testdata/certificates, of certificates the C#
/// package issues, and its DER of distinguished names.
/// </summary>
internal static class CertificateFixtures
{
    public static void Write(PkiOutput o)
    {
        string certificates = Path.GetFullPath(Path.Combine(o.Directory, "..", "..", "certificates"));
        var real = new JsonObject();
        foreach (string path in System.IO.Directory.GetFiles(certificates, "*", SearchOption.AllDirectories)
                     .Where(f => f.EndsWith(".cer", StringComparison.Ordinal) || f.EndsWith(".crt", StringComparison.Ordinal))
                     .Order(StringComparer.Ordinal))
        {
            string relative = Path.GetRelativePath(certificates, path).Replace('\\', '/');
            real[relative] = Describe(File.ReadAllBytes(path));
        }
        Expect(real.Count >= 12, "every real certificate was read");
        o.WriteJson("certificates/real.json", new JsonObject
        {
            ["about"] = "keys are paths under testdata/certificates; fields as BouncyCastle 2.7.0 reads them, the key as UaPki.ReadPublicKey reads it",
            ["certificates"] = real,
        });

        o.WriteJson("certificates/distinguished-names.json", DistinguishedNames());
        o.WriteJson("certificates/package-issued.json", PackageIssued(o));
        o.WriteText("certificates/README.md", Readme);
    }

    private static JsonObject Describe(byte[] der)
    {
        BcCertificate bc = UaPki.ParseCertificate(der);
        var (parameters, publicKey, dke) = UaPki.ReadPublicKey(bc);
        Certificate ours = Certificate.Load(der);

        // The assertions of CertificateTests.RealCertificateParsesLikeBouncyCastle, here against the C# package.
        Expect(bc.SubjectDN.GetDerEncoded().AsSpan().SequenceEqual(ours.Subject.Encoded) && bc.GetTbsCertificate().AsSpan().SequenceEqual(ours.TbsEncoded)
            && bc.SerialNumber.ToString() == ours.SerialNumber.ToString() && ours.PublicKey.Q.AffineX.ToBigInteger() == publicKey.AffineX.ToBigInteger(),
            "the package parses a real certificate like BouncyCastle");
        Expect(Time(bc.NotBefore) == Time(ours.NotBefore) && Time(bc.NotAfter) == Time(ours.NotAfter), "validity like the package");

        return new JsonObject
        {
            ["version"] = bc.Version,
            ["serialNumber"] = bc.SerialNumber.ToString(),
            ["subject"] = Hex(bc.SubjectDN.GetDerEncoded()),
            ["issuer"] = Hex(bc.IssuerDN.GetDerEncoded()),
            ["notBefore"] = Time(bc.NotBefore),
            ["notAfter"] = Time(bc.NotAfter),
            ["signatureAlgorithm"] = bc.SigAlgOid,
            ["tbsCertificate"] = Hex(bc.GetTbsCertificate()),
            ["signature"] = Hex(bc.GetSignature()),
            ["subjectPublicKeyInfo"] = Hex(bc.CertificateStructure.SubjectPublicKeyInfo.GetDerEncoded()),
            ["extensionCount"] = bc.GetNonCriticalExtensionOids().Count + bc.GetCriticalExtensionOids().Count,
            ["isCa"] = bc.GetBasicConstraints() >= 0,
            ["key"] = new JsonObject
            {
                ["m"] = parameters.Field.M,
                ["n"] = Hex(parameters.N),
                ["qx"] = Hex(publicKey.AffineX.ToBigInteger()),
                ["qy"] = Hex(publicKey.AffineY.ToBigInteger()),
                ["dke"] = dke is null ? null : Hex(dke),
            },
        };
    }

    private static JsonObject DistinguishedNames()
    {
        const string ascii = "CN=Test Signer,O=UA Cryptography Tests,OU=Unit,L=Kyiv,C=UA,SERIALNUMBER=UA-12345";
        DistinguishedName cyrillic = DistinguishedName.Parse("CN=Тестовий підписувач, O=Організація\\, ТОВ, C=UA");
        string cyrillicText = cyrillic.ToString();
        byte[] asciiDer = new X509Name(ascii).GetDerEncoded();
        byte[] cyrillicDer = new X509Name(cyrillicText).GetDerEncoded();
        Expect(asciiDer.AsSpan().SequenceEqual(DistinguishedName.Parse(ascii).Encoded), "ASCII DN like BouncyCastle");
        Expect(cyrillicDer.AsSpan().SequenceEqual(cyrillic.Encoded), "Cyrillic DN like BouncyCastle");
        return new JsonObject
        {
            ["about"] = "new X509Name(text).GetDerEncoded() (BouncyCastle 2.7.0); CertificateTests.DistinguishedNameEncodesLikeBouncyCastle",
            ["names"] = new JsonArray(
                new JsonObject { ["text"] = ascii, ["der"] = Hex(asciiDer) },
                new JsonObject
                {
                    ["text"] = cyrillicText,
                    ["parsedFrom"] = "CN=Тестовий підписувач, O=Організація\\, ТОВ, C=UA",
                    ["about"] = "the package's ToString() of the parsed name, then BouncyCastle's DER of that text",
                    ["der"] = Hex(cyrillicDer),
                    ["commonName"] = cyrillic.Get(PkiOids.CommonName),
                    ["organization"] = cyrillic.Get(PkiOids.Organization),
                }),
        };
    }

    /// <summary>CertificateTests.IssuedCertificatesAreAcceptedByBouncyCastleAndUaPki: the package's certificates as BouncyCastle reads them.</summary>
    private static JsonArray PackageIssued(PkiOutput o)
    {
        var cases = new JsonArray();
        foreach (var (algorithm, m) in new[] { (Oids.Dstu4145WithDstu7564, 257), (Oids.Dstu4145WithGost34311, 431), (Oids.Dstu4145WithDstu7564, 163) })
        {
            Dstu4145PrivateKey rootKey = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(m));
            Certificate root = new CertificateBuilder(DistinguishedName.Parse("CN=Package Root,O=UA Cryptography Tests,C=UA"), rootKey.PublicKey)
            {
                SignatureAlgorithm = algorithm,
            }.AddBasicConstraints(true).AddKeyUsage(KeyUsageFlags.KeyCertSign | KeyUsageFlags.CrlSign).AddSubjectKeyIdentifier().SelfSign(rootKey);
            Dstu4145PrivateKey leafKey = Dstu4145PrivateKey.Generate(Dstu4145NamedCurves.Polynomial(257));
            Certificate leaf = new CertificateBuilder(DistinguishedName.Parse("CN=Package Leaf,O=UA Cryptography Tests,C=UA"), leafKey.PublicKey)
            {
                SignatureAlgorithm = algorithm,
            }
                .AddBasicConstraints(false)
                .AddKeyUsage(KeyUsageFlags.DigitalSignature | KeyUsageFlags.NonRepudiation)
                .AddAuthorityKeyIdentifier(root.SubjectKeyIdentifier!)
                .AddAuthorityInfoAccess("http://ocsp.example/", "http://ca.example/ca.cer")
                .AddTimeStampingUrl("http://tsp.example/")
                .Issue(root, rootKey);

            string name = $"{TspOcspFixtures.Short(UaPki.HashOf(algorithm))}-{m}";
            string rootFile = o.WriteCertificate($"certificates/package-issued/root-{name}.cer", root.Encoded);
            string leafFile = o.WriteCertificate($"certificates/package-issued/leaf-{name}.cer", leaf.Encoded);
            BcCertificate bcRoot = UaPki.ParseCertificate(root.Encoded);
            BcCertificate bcLeaf = UaPki.ParseCertificate(leaf.Encoded);
            Expect(UaPki.VerifyCertificate(bcRoot, bcRoot) && UaPki.VerifyCertificate(bcLeaf, bcRoot), "UaPki verifies the package's certificates");
            Expect(bcLeaf.GetKeyUsage().SequenceEqual([true, true, false, false, false, false, false, false, false]), "key usage");
            cases.Add(new JsonObject
            {
                ["signatureAlgorithm"] = algorithm,
                ["rootM"] = m,
                ["root"] = BouncyCastleView(rootFile, bcRoot, rootKey),
                ["leaf"] = BouncyCastleView(leafFile, bcLeaf, leafKey),
                ["leafSignedByRoot"] = UaPki.VerifyCertificate(bcLeaf, bcRoot),
            });
        }
        return cases;
    }

    private static JsonObject BouncyCastleView(string file, BcCertificate bc, Dstu4145PrivateKey key)
    {
        var (_, publicKey, _) = UaPki.ReadPublicKey(bc);
        return new JsonObject
        {
            ["file"] = file,
            ["d"] = Hex(key.D),
            ["sigAlgOid"] = bc.SigAlgOid,
            ["basicConstraints"] = bc.GetBasicConstraints(),
            ["keyUsage"] = bc.GetKeyUsage() is { } usage ? new JsonArray(usage.Select(b => (JsonNode)b).ToArray()) : null,
            ["subject"] = Hex(bc.SubjectDN.GetDerEncoded()),
            ["issuer"] = Hex(bc.IssuerDN.GetDerEncoded()),
            ["extensionOids"] = Array(bc.GetCriticalExtensionOids().Concat(bc.GetNonCriticalExtensionOids()).Order(StringComparer.Ordinal)),
            ["qx"] = Hex(publicKey.AffineX.ToBigInteger()),
            ["qy"] = Hex(publicKey.AffineY.ToBigInteger()),
            ["selfSignatureVerifies"] = UaPki.VerifyCertificate(bc, bc),
        };
    }

    private const string Readme = """
        # certificates/

        What BouncyCastle 2.7.0 reads from certificates, recorded by `tools/csharp-oracle -- pki`, so the Rust X.509 parser
        can be compared field by field without BouncyCastle.

        | File | What | C# test |
        |------|------|---------|
        | `real.json` | every real certificate under `testdata/certificates/**` (`*.cer`, `*.crt`; the same files as the C# `TestData/certificates`), keyed by path: version, serial (decimal), subject and issuer DER, validity, signature algorithm, DER TBSCertificate, signature BIT STRING content, SubjectPublicKeyInfo DER, number of extensions, `isCa` (basicConstraints), and the key as `UaPki.ReadPublicKey` reads it (m, n, Q, DKE) | `Pki/X509/CertificateTests.RealCertificateParsesLikeBouncyCastle` (also the BouncyCastle side of `CzoTrustAnchorTests`, `ChainToTrustAnchorTests`, `HistoricalCertificateTests`) |
        | `distinguished-names.json` | `new X509Name(text).GetDerEncoded()` for the ASCII DN of the test and for the C# package's `ToString()` of the Cyrillic DN | `Pki/X509/CertificateTests.DistinguishedNameEncodesLikeBouncyCastle` |
        | `package-issued.json`, `package-issued/*.cer` | certificates the C# package's `CertificateBuilder` issues (root with basicConstraints, keyUsage, SKI; leaf with AKI, AIA, time-stamping URL) for (DSTU 7564, 257), (GOST 34.311, 431), (DSTU 7564, 163), and how BouncyCastle reads them (sigAlg, basicConstraints, keyUsage bits, extensions, Q, self-signature) | `Pki/X509/CertificateTests.IssuedCertificatesAreAcceptedByBouncyCastleAndUaPki` (the Rust test issues its own certificates and checks them with Rust recipes; these files show what the reference builder makes and BouncyCastle accepts) |
        """;
}
