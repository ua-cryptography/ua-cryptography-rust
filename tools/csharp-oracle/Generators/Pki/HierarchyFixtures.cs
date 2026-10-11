using System.Text.Json.Nodes;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Gost;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.X509;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;
using static CSharpOracle.Generators.PkiOutput;

namespace CSharpOracle.Generators;

/// <summary>hierarchy/: the certificates and keys of Hierarchy.Shared, its "good" OCSP responses and the signer's twin.</summary>
internal static class HierarchyFixtures
{
    public const string SignerOcsp = "hierarchy/ocsp-signer.der";
    public const string IssuingCaOcsp = "hierarchy/ocsp-issuing-ca.der";
    public const string Twin = "hierarchy/signer-twin.cer";

    public static void Write(PkiOutput o)
    {
        Hierarchy pki = o.Pki;
        (string Name, TestPki.TestIdentity Identity, string Issuer, string Role)[] identities =
        [
            ("root", pki.Root, "root", "self-signed root CA, m = 431 (like the Central Certification Authority)"),
            ("issuing-ca", pki.IssuingCa, "root", "issuing CA (like a qualified trust service provider)"),
            ("signer", pki.Signer, "issuing-ca", "the end-entity key that signs documents"),
            ("tsa", pki.Tsa.Identity, "root", "time-stamping service (extendedKeyUsage timeStamping)"),
            ("ocsp", pki.IssuingCaOcsp.Identity, "issuing-ca", "OCSP responder for the issuing CA's certificates (extendedKeyUsage OCSPSigning)"),
            ("root-ocsp", pki.RootOcsp.Identity, "root", "OCSP responder for the root's certificates (extendedKeyUsage OCSPSigning)"),
        ];

        var json = new JsonObject();
        foreach (var (name, identity, issuer, role) in identities)
        {
            string file = o.WriteCertificate($"hierarchy/{name}.cer", identity.Certificate.GetEncoded());
            json[name] = Identity(file, identity, issuer, role);
        }
        o.RootFile = o.FileOf(pki.Root.Certificate);
        o.AllCertificates = [o.FileOf(pki.Signer.Certificate), .. pki.ValidationCertificates.Select(o.FileOf)];

        // "good" OCSP responses for the signer and its CA, from their issuers' responders (Hierarchy.SignerRevocationData).
        o.Write(SignerOcsp, OcspResponder.Encode(pki.IssuingCaOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate)));
        o.Write(IssuingCaOcsp, OcspResponder.Encode(pki.RootOcsp.Respond(pki.IssuingCa.Certificate, pki.Root.Certificate)));

        // A second certificate for the signer's key with the same subject, issuer and serial number (CadesSignerTests).
        Certificate signer = pki.Signer.Certificate.ToPki();
        Certificate twin = new CertificateBuilder(signer.Subject, pki.Signer.Key.ToPki().PublicKey) { SerialNumber = signer.SerialNumber }
            .Issue(pki.IssuingCa.Certificate.ToPki(), pki.IssuingCa.Key.ToPki());
        o.WriteCertificate(Twin, twin.Encoded);

        o.WriteJson("hierarchy/keys.json", new JsonObject
        {
            ["identities"] = json,
            ["signerChain"] = Array(pki.SignerChain.Select(o.FileOf)),
            ["validationCertificates"] = Array(pki.ValidationCertificates.Select(o.FileOf)),
            ["allCertificates"] = Array(o.AllCertificates),
            ["ocsp"] = new JsonObject
            {
                [SignerOcsp] = "good, about signer.cer, by ocsp.cer (IssuingCaOcsp.Respond(Signer, IssuingCa))",
                [IssuingCaOcsp] = "good, about issuing-ca.cer, by root-ocsp.cer (RootOcsp.Respond(IssuingCa, Root))",
            },
            ["twin"] = new JsonObject
            {
                ["certificate"] = Twin,
                ["about"] = "made by the C# package's CertificateBuilder: signer.cer's subject, key and serial number, issued by issuing-ca",
            },
        });
        o.WriteText("hierarchy/README.md", Readme);
        Check(o, twin);
    }

    private static JsonObject Identity(string file, TestPki.TestIdentity identity, string issuer, string role)
    {
        BcCertificate c = identity.Certificate;
        TestPki.TestKey key = identity.Key;
        int index = Dstu4145NamedCurves.PolynomialDegrees.ToList().IndexOf(key.M);
        return new JsonObject
        {
            ["role"] = role,
            ["certificate"] = file,
            ["subject"] = c.SubjectDN.ToString(),
            ["issuer"] = issuer,
            ["serialNumber"] = c.SerialNumber.ToString(),
            ["notBefore"] = Time(c.NotBefore),
            ["notAfter"] = Time(c.NotAfter),
            ["signatureAlgorithm"] = c.SigAlgOid,
            ["isCa"] = c.GetBasicConstraints() >= 0,
            ["extendedKeyUsage"] = c.GetExtendedKeyUsage() is { Count: > 0 } eku ? Array(eku.Select(p => p.Id)) : null,
            ["key"] = new JsonObject
            {
                ["m"] = key.M,
                ["basis"] = "polynomial",
                ["namedCurveIndex"] = index,
                ["namedCurveOid"] = Oids.NamedCurvePrefix + index,
                ["d"] = Hex(key.PrivateKey),
                ["qx"] = Hex(key.PublicKey.AffineX.ToBigInteger()),
                ["qy"] = Hex(key.PublicKey.AffineY.ToBigInteger()),
                ["dke"] = Hex(key.Dke),
                ["dkeIsDefault"] = key.Dke.AsSpan().SequenceEqual(Gost34311.DefaultDke),
                ["publicKeyOid"] = Oids.Dstu4145Le,
            },
        };
    }

    private static void Check(PkiOutput o, Certificate twin)
    {
        Hierarchy pki = o.Pki;
        BcCertificate[] all = [pki.Signer.Certificate, .. pki.ValidationCertificates];
        foreach (BcCertificate c in all)
            Expect(UaPki.ChainsToTrusted(c, all, [pki.Root.Certificate]), $"{c.SubjectDN} chains to the root (UaPki)");

        Certificate ca = pki.IssuingCa.Certificate.ToPki();
        Expect(pki.Signer.Certificate.ToPki().IsSignedBy(ca) && twin.IsSignedBy(ca), "signer and twin are signed by the CA (package)");
        Expect(!twin.Encoded.AsSpan().SequenceEqual(pki.Signer.Certificate.GetEncoded()), "the twin differs from the signer certificate");

        Certificate signer = pki.Signer.Certificate.ToPki();
        OcspResponse good = OcspResponse.Load(o.Read(SignerOcsp));
        Expect(good.Find(signer, ca)?.Status == OcspCertificateStatus.Good, "signer OCSP is good");
        Expect(good.IsSignedBy(pki.IssuingCaOcsp.Identity.Certificate.ToPki()), "signer OCSP is signed by its responder");
        OcspResponse caGood = OcspResponse.Load(o.Read(IssuingCaOcsp));
        Expect(caGood.Find(ca, pki.Root.Certificate.ToPki())?.Status == OcspCertificateStatus.Good, "CA OCSP is good");
    }

    private const string Readme = """
        # hierarchy/

        The synthetic PKI every C# PKI test is built on (`tests/UA.Cryptography.Tests/Support/Hierarchy.cs`,
        `Hierarchy.Shared`), recorded once by `tools/csharp-oracle` (`dotnet run --project tools/csharp-oracle -- pki`).
        Keys are generated at random on each run; nothing here names a real person.

        ```
        Test Root CA            root.cer        self-signed, m = 431, DSTU 4145 + DSTU 7564
        ├── Test Issuing CA     issuing-ca.cer  m = 257
        │   ├── Test Signer     signer.cer      m = 257, the key that signs documents
        │   └── Test OCSP       ocsp.cer        answers for the Issuing CA's certificates
        ├── Test TSP Server     tsa.cer         m = 257, time-stamps
        └── Test Root OCSP      root-ocsp.cer   answers for the root's certificates
        ```

        | File | What |
        |------|------|
        | `*.cer` | DER certificates built by `TestPki` (BouncyCastle assembles the ASN.1, the library signs) |
        | `keys.json` | per identity: role, certificate file, subject, serial (decimal), validity, signature algorithm, and the key: degree `m`, named-curve index / OID (table Г.1), `d` (big-endian hex), public point `qx`/`qy` (big-endian hex), DKE (hex, GOST 34.311 S-box DKE No. 1); also the signer chain, `validationCertificates` and `allCertificates` (C# `PkiLayer.AllCertificates`: signer first) |
        | `ocsp-signer.der` | full OCSPResponse "good" about `signer.cer` from `ocsp.cer` (`IssuingCaOcsp.Respond(Signer, IssuingCa)`) |
        | `ocsp-issuing-ca.der` | full OCSPResponse "good" about `issuing-ca.cer` from `root-ocsp.cer` (`RootOcsp.Respond(IssuingCa, Root)`) |
        | `signer-twin.cer` | a second certificate for the signer's key with the same subject, issuer and serial number, made by the C# package's `CertificateBuilder` (`CadesSignerTests.ForeignCertificateFailsTheSigningCertificateCheck`) |

        The certificates are valid from one day before the run for five years. Signatures in the sibling folders carry a
        signing time and a time-stamp, so their validation time is the time they were made, not the time the test runs.

        Stands in for `Hierarchy.Shared` in every Rust port of `Pki/**` and `Signatures/**`: `TestPkiTests`
        (`HierarchyMirrorsTheNationalChain`, `OcspResponseIsSignedByTheResponderAndGood`), `CertificateTests.SyntheticHierarchyVerifiesWithThePackage`,
        `ChainToTrustAnchorTests.SyntheticChainIsRejectedByCzoTrust` / `ChainWithForeignIssuerIsRejected`,
        `PathValidationTests` (with `ocsp/`), `JksKeyStoreTests` (keys for the stores the Rust test writes), and the keys a Rust
        test needs to issue certificates of its own (impostor roots, a leaf below a leaf) or to run an in-process TSA / OCSP
        responder (`tsa` and `ocsp` keys).
        """;
}
