using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using UA.Cryptography.Pki;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Services;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace CSharpOracle.Generators;

/// <summary>
/// One run of the pki generator: the output folder, the shared synthetic hierarchy, the certificate file names, and the
/// signature manifest. Every signature added to the manifest is verified here with the C# package before it is kept.
/// </summary>
internal sealed class PkiOutput(string directory, Hierarchy pki)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private readonly Dictionary<string, string> _certificateFiles = new(StringComparer.Ordinal);
    private readonly JsonArray _manifest = [];

    public string Directory { get; } = directory;

    public Hierarchy Pki { get; } = pki;

    /// <summary>Hierarchy files: what C# PkiLayer.AllCertificates holds (signer first, then ValidationCertificates).</summary>
    public string[] AllCertificates { get; set; } = [];

    public string RootFile { get; set; } = "";

    // ---- files ---------------------------------------------------------------------------------------------------

    /// <summary>Writes <paramref name="content"/> at <paramref name="relative"/> (relative to testdata/oracle/pki) and returns that path.</summary>
    public string Write(string relative, byte[] content)
    {
        string path = Path.Combine(Directory, relative);
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, content);
        return relative;
    }

    public string WriteText(string relative, string text) =>
        Write(relative, new UTF8Encoding(false).GetBytes(text.ReplaceLineEndings("\n").TrimEnd('\n') + "\n"));

    public string WriteJson(string relative, JsonNode node) => WriteText(relative, node.ToJsonString(JsonOptions) + "\n");

    public byte[] Read(string relative) => File.ReadAllBytes(Path.Combine(Directory, relative));

    /// <summary>Remembers the file of a certificate, so that later JSON can name it.</summary>
    public string WriteCertificate(string relative, byte[] der)
    {
        Write(relative, der);
        _certificateFiles[Hex(der)] = relative;
        return relative;
    }

    public string FileOf(byte[] der) =>
        _certificateFiles.TryGetValue(Hex(der), out string? file) ? file : throw new InvalidOperationException("Certificate was not written.");

    public string FileOf(BcCertificate certificate) => FileOf(certificate.GetEncoded());

    public string FileOf(Certificate certificate) => FileOf(certificate.Encoded);

    public Certificate LoadCertificate(string relative) => Certificate.Load(Read(relative));

    // ---- formatting ----------------------------------------------------------------------------------------------

    public static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    /// <summary>A non-negative integer as big-endian hex without leading zero bytes ("00" for zero).</summary>
    public static string Hex(BigInteger value) => value.IsZero ? "00" : Hex(value.ToByteArray(isUnsigned: true, isBigEndian: true));

    public static string Time(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    /// <summary>A BouncyCastle time: Local is converted, Unspecified is taken as UTC.</summary>
    public static string Time(DateTime time) =>
        Time(new DateTimeOffset(time.Kind == DateTimeKind.Local ? time.ToUniversalTime() : DateTime.SpecifyKind(time, DateTimeKind.Utc)));

    public static JsonArray Array(IEnumerable<string> items) => new(items.Select(i => (JsonNode)JsonValue.Create(i)!).ToArray());

    public static void Expect(bool condition, string what)
    {
        if (!condition)
            throw new InvalidOperationException($"pki oracle self-check failed: {what}");
    }

    // ---- manifest ------------------------------------------------------------------------------------------------

    /// <summary>The verification C# tests call "Trusting": the hierarchy's root as anchor, every hierarchy certificate as extra.</summary>
    public Verification Trusting(bool valid = true, params (string Name, CheckStatus Status)[] required) =>
        new([RootFile], AllCertificates, valid) { Required = required };

    /// <summary>Verifies a signature file with every verification given, fails on any surprise, and lists it in the manifest.</summary>
    public void AddSignature(SignatureFixture fixture)
    {
        byte[] signature = Read(fixture.File);
        var verifications = new JsonArray();
        foreach (Verification v in fixture.Verifications)
        {
            VerificationResult result = SignatureVerifier.Verify(signature, name => Resolve(fixture, name), Options(v));
            string checks = Describe(result);
            Expect(result.IsValid == v.Valid, $"{fixture.File}: expected valid = {v.Valid}\n{checks}");
            foreach ((string name, CheckStatus status) in v.Required)
            {
                Expect(result.Signatures.SelectMany(s => s.Checks).Any(c => c.Name == name && c.Status == status),
                    $"{fixture.File}: no check '{name}' with status {status}\n{checks}");
            }
            verifications.Add(v.ToJson(result));
        }

        _manifest.Add(new JsonObject
        {
            ["file"] = fixture.File,
            ["format"] = fixture.Format,
            ["level"] = fixture.Level,
            ["hashOid"] = fixture.HashOid,
            ["packaging"] = fixture.Packaging,
            ["contentTimeStamp"] = fixture.ContentTimeStamp,
            ["producer"] = fixture.Producer,
            ["data"] = new JsonArray(fixture.Data.Select(d => (JsonNode)new JsonObject { ["name"] = d.Name, ["file"] = d.File }).ToArray()),
            ["verifications"] = verifications,
            ["csharpTests"] = Array(fixture.CSharpTests),
        });
    }

    public void WriteManifest() => WriteJson("manifest.json", new JsonObject
    {
        ["description"] = "Every signature fixture under testdata/oracle/pki with the verdicts of the C# package (see README.md).",
        ["paths"] = "relative to testdata/oracle/pki",
        ["signatures"] = _manifest,
    });

    private byte[]? Resolve(SignatureFixture fixture, string? name)
    {
        if (name is null)
            return fixture.Data.Count == 1 ? Read(fixture.Data[0].File) : null;
        (string Name, string File)? match = fixture.Data.Cast<(string, string)?>().FirstOrDefault(d => d!.Value.Item1 == name);
        return match is null ? null : Read(match.Value.File);
    }

    private ValidationOptions Options(Verification v) => new()
    {
        TrustAnchors = v.TrustAnchors.Select(LoadCertificate).ToList(),
        ExtraCertificates = v.ExtraCertificates.Select(LoadCertificate).ToList(),
        Downloads = v.Downloads is null ? null : new RecordedDownloads(this, v.Downloads),
        OnlineOcsp = v.OnlineOcsp is null ? null : new RecordedOcsp(this, v.OnlineOcsp),
    };

    public static string Describe(VerificationResult result) => string.Join("\n", result.Signatures.SelectMany(
        r => r.Checks.Select(c => $"{r.Title}: [{c.Status}] {c.Name}: {c.Details}")));

    /// <summary>Answers downloads from recorded certificate files.</summary>
    private sealed class RecordedDownloads(PkiOutput output, IReadOnlyDictionary<string, string[]> map) : ICertificateSource
    {
        public IReadOnlyList<Certificate> Download(string url) =>
            map.TryGetValue(url, out string[]? files) ? files.Select(output.LoadCertificate).ToList() : [];
    }

    /// <summary>Answers OCSP requests with recorded responses, by the certificate asked about.</summary>
    private sealed class RecordedOcsp(PkiOutput output, IReadOnlyDictionary<string, string> map) : IOcspService
    {
        public OcspResponse? GetResponse(Certificate certificate, Certificate issuer, string hashOid) =>
            map.TryGetValue(output.FileOf(certificate), out string? file) ? OcspResponse.Load(output.Read(file)) : null;
    }
}

/// <summary>A signature fixture of the manifest.</summary>
internal sealed record SignatureFixture(
    string File,
    string Format,
    string Level,
    string HashOid,
    string Packaging,
    bool ContentTimeStamp,
    string Producer,
    IReadOnlyList<(string Name, string File)> Data,
    IReadOnlyList<Verification> Verifications,
    IReadOnlyList<string> CSharpTests);

/// <summary>One way to verify a fixture (ValidationOptions as files) and the C# package's verdict.</summary>
internal sealed record Verification(string[] TrustAnchors, string[] ExtraCertificates, bool Valid)
{
    /// <summary>caIssuers URL → certificate files the download returns.</summary>
    public Dictionary<string, string[]>? Downloads { get; init; }

    /// <summary>Certificate file → recorded OCSP response the online service returns for it.</summary>
    public Dictionary<string, string>? OnlineOcsp { get; init; }

    /// <summary>Checks the C# tests assert on (name, status); the generator fails if one is missing.</summary>
    public (string Name, CheckStatus Status)[] Required { get; init; } = [];

    public JsonObject ToJson(VerificationResult result)
    {
        var json = new JsonObject
        {
            ["trustAnchors"] = PkiOutput.Array(TrustAnchors),
            ["extraCertificates"] = PkiOutput.Array(ExtraCertificates),
        };
        if (Downloads is not null)
            json["downloads"] = new JsonObject(Downloads.Select(d => KeyValuePair.Create(d.Key, (JsonNode?)PkiOutput.Array(d.Value))));
        if (OnlineOcsp is not null)
            json["onlineOcsp"] = new JsonObject(OnlineOcsp.Select(d => KeyValuePair.Create(d.Key, (JsonNode?)JsonValue.Create(d.Value))));
        json["valid"] = Valid;
        json["format"] = result.Format;
        json["requiredChecks"] = new JsonArray(Required.Select(r => (JsonNode)new JsonObject { ["name"] = r.Name, ["status"] = r.Status.ToString() }).ToArray());
        json["reports"] = new JsonArray(result.Signatures.Select(r => (JsonNode)new JsonObject
        {
            ["title"] = r.Title,
            ["valid"] = r.IsValid,
            ["format"] = r.Format,
            ["checks"] = PkiOutput.Array(r.Checks.Select(c => $"{c.Status}: {c.Name}")),
        }).ToArray());
        return json;
    }
}
