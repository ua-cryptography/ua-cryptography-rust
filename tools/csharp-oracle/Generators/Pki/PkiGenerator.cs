namespace CSharpOracle.Generators;

/// <summary>
/// testdata/oracle/pki/: everything the Rust PKI tests need from the C# test oracles (BouncyCastle, the synthetic PKI,
/// the CAdES / XAdES / provider builders, Support/Jks.cs) and from the C# package itself, made from one shared
/// Hierarchy in one process. Every signature is verified by the C# package before it is kept.
/// </summary>
internal sealed class PkiGenerator : IFixtureGenerator
{
    public string Name => "pki";

    public void Generate(string directory)
    {
        foreach (string sub in Directory.GetDirectories(directory))
            Directory.Delete(sub, recursive: true);
        foreach (string file in Directory.GetFiles(directory))
            File.Delete(file);

        var output = new PkiOutput(directory, Hierarchy.Shared);
        HierarchyFixtures.Write(output);
        TspOcspFixtures.Write(output);
        BuilderFixtures.Write(output);
        ProviderFixtures.Write(output);
        JksFixtures.Write(output);
        CertificateFixtures.Write(output);
        PackageFixtures.Write(output);
        output.WriteManifest();
        output.WriteText("README.md", Readme);
    }

    private const string Readme = """
        # testdata/oracle/pki

        Fixtures for the Rust ports of the C# PKI tests (`tests/UA.Cryptography.Tests/Pki/**`, `Signatures/**`), which use
        BouncyCastle and the BouncyCastle-based test support code at run time. Produced once by the C# oracle tool from one
        shared synthetic hierarchy in one process:

        ```bash
        dotnet run --project tools/csharp-oracle -- pki    # rewrites this folder; keys are random on every run
        ```

        Generator: `tools/csharp-oracle/Generators/Pki/*.cs`. Everything is synthetic (generated keys, "UA Cryptography
        Tests" names). Every signature listed in `manifest.json` was verified by the C# package (`SignatureVerifier`) with
        the options recorded next to it before it was written; the run fails otherwise.

        | Folder | What | C# tests it stands in for |
        |--------|------|---------------------------|
        | `hierarchy/` | the certificates, keys and "good" OCSP responses of `Hierarchy.Shared`, the signer's twin certificate | `Hierarchy.Shared` everywhere |
        | `cades/` | every `CadesBuilder` variant and ASiC-S | `CadesSignerTests.TestBuilder…`, `Signatures/CadesTests`, `AsicContainerTests.TestBuilderContainersVerify` |
        | `xades/` | every `XadesBuilder` variant, detached and in ASiC-E; C14N oracle | `XadesSignerTests.TestBuilder…`, `Signatures/XadesTests`, `XmlCanonicalizerTests.XadesBuilderDocumentMatchesMicrosoft` |
        | `providers/` | PrivatBank `.sig` and "Дія" ASiC-E as the providers and as the C# `ua-sign` make them | `Signatures/ProviderFormatTests` |
        | `tsp/`, `ocsp/` | time-stamp tokens, responses and requests; OCSP special cases | `TimeStampTokenTests`, `TestPkiTests`, `PathValidationTests`, `HttpServicesTests` |
        | `jks/` | key stores by `Support/Jks.cs` and by the C# package, PKCS#8 forms | `JksKeyStoreTests`, `TestPkiTests` |
        | `certificates/` | BouncyCastle's reading of the real certificates, of package-issued ones, DN encodings | `CertificateTests` |
        | `package/` | signatures made by the C# package (CAdES, XAdES, ASiC-S/E at B, T, LT) | `CadesSignerTests`, `XadesSignerTests`, `AsicContainerTests` |

        `manifest.json` lists every signature fixture: `file`, `format` (CAdES, XAdES, ASiC-S, ASiC-E), `level`,
        `hashOid`, `packaging`, `contentTimeStamp`, `producer`, `data` (signed name → file; a detached CAdES is resolved with
        the only entry), `verifications` (each: `trustAnchors`, `extraCertificates`, optional `downloads` (URL → certificate
        files) and `onlineOcsp` (certificate file → response file), the expected `valid` verdict, `requiredChecks` the C#
        tests assert, and the C# package's `reports` with every check as `Status: name`), and `csharpTests`. All paths are
        relative to this folder.

        The hierarchy's certificates are valid for five years from the run; signatures are validated at their signing or
        time-stamp time, so the verdicts do not depend on the day the Rust tests run — except a Rust test that validates a
        bare certificate path "now", which needs the run to be younger than five years (regenerate then).

        Not recorded (no oracle needed or not possible): tampered copies (the Rust tests tamper themselves), PAdES (the
        library has none), `Pki/Asn1/DerTests` (BouncyCastle DER primitives: the ua-cryptography-der crate's own fixtures),
        `XmlCanonicalizerTests` other than the XAdES document (the ua-cryptography-xml-c14n crate's own fixtures).
        """;
}
