using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Cms;
using UA.Cryptography.Pki.Ocsp;
using UA.Cryptography.Pki.Tsp;
using UA.Cryptography.Pki.Validation;
using UA.Cryptography.Pki.X509;
using static CSharpOracle.Generators.PkiOutput;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using BcOcspReq = Org.BouncyCastle.Ocsp.OcspReq;
using BcTimeStampRequest = Org.BouncyCastle.Tsp.TimeStampRequest;
using BcTimeStampToken = Org.BouncyCastle.Tsp.TimeStampToken;
using OcspResponse = UA.Cryptography.Pki.Ocsp.OcspResponse;

namespace CSharpOracle.Generators;

/// <summary>
/// tsp/ and ocsp/: tokens of the hierarchy's TSA and OCSP responses with their special cases, the protocol messages
/// of LocalPkiServer (TimeStampResp), and what BouncyCastle reads from the package's requests.
/// </summary>
internal static class TspOcspFixtures
{
    private static readonly byte[] Covered = "covered bytes"u8.ToArray();
    private static readonly byte[] OtherData = "data"u8.ToArray();

    public static void Write(PkiOutput o)
    {
        WriteTsp(o);
        WriteOcsp(o);
    }

    // ---- tsp/ ----------------------------------------------------------------------------------------------------

    private static void WriteTsp(PkiOutput o)
    {
        Hierarchy pki = o.Pki;
        string covered = o.Write("tsp/covered.bin", Covered);
        string other = o.Write("tsp/data.bin", OtherData);
        var tokens = new JsonArray();
        foreach (string hashOid in new[] { Oids.Dstu7564_256, Oids.Gost34311 })
        {
            foreach (bool embedded in new[] { true, false })
            {
                string file = $"tsp/token-{Short(hashOid)}{(embedded ? "" : "-no-certificate")}.der";
                o.Write(file, pki.Tsa.Stamp(Covered, hashOid, includeCertificate: embedded));
                tokens.Add(DescribeToken(o, file, covered, embedded));
                CheckToken(o, file, embedded);
            }
        }
        string overData = o.Write("tsp/token-dstu7564-over-data.der", pki.Tsa.Stamp(OtherData, Oids.Dstu7564_256));
        tokens.Add(DescribeToken(o, overData, other, embedded: true));
        CheckToken(o, overData, embedded: true, covered: OtherData);

        // LocalPkiServer's answer to a request (granted, with the request's nonce) and a refusal.
        byte[] hash = new byte[32];
        BigInteger nonce = TimeStampProtocol.NewNonce();
        byte[] token = pki.Tsa.StampHash(hash, Oids.Dstu7564_256, nonce: new BcBigInteger(nonce.ToString()));
        string granted = o.Write("tsp/response-granted.der",
            new TimeStampResp(new PkiStatusInfo(0), BcContentInfo.GetInstance(Asn1Object.FromByteArray(token))).GetDerEncoded());
        string rejection = o.Write("tsp/response-rejection.der", new TimeStampResp(new PkiStatusInfo(2), null).GetDerEncoded());
        Expect(TimeStampProtocol.ParseResponse(o.Read(granted), hash, Oids.Dstu7564_256, nonce).Nonce == nonce, "granted response parses");
        Throws(() => TimeStampProtocol.ParseResponse(o.Read(granted), Enumerable.Repeat((byte)1, 32).ToArray(), Oids.Dstu7564_256, nonce), "other imprint");
        Throws(() => TimeStampProtocol.ParseResponse(o.Read(granted), hash, Oids.Dstu7564_256, nonce + 1), "other nonce");
        Throws(() => TimeStampProtocol.ParseResponse(o.Read(rejection), hash, Oids.Dstu7564_256, nonce), "rejection");

        // Requests made by the package, as BouncyCastle (LocalPkiServer) reads them.
        var requests = new JsonArray();
        foreach (string hashOid in new[] { Oids.Dstu7564_256, Oids.Gost34311 })
        {
            byte[] imprint = UaPki.Hash(hashOid, Covered);
            BigInteger requestNonce = TimeStampProtocol.NewNonce();
            string file = o.Write($"tsp/request-{Short(hashOid)}.der", TimeStampProtocol.CreateRequest(imprint, hashOid, requestNonce));
            var bc = new BcTimeStampRequest(o.Read(file));
            Expect(bc.MessageImprintAlgOid == hashOid && bc.GetMessageImprintDigest().SequenceEqual(imprint) && bc.CertReq
                && bc.Nonce.ToString() == requestNonce.ToString(), "BouncyCastle reads the package's TimeStampReq");
            requests.Add(new JsonObject
            {
                ["file"] = file,
                ["madeBy"] = "UA.Cryptography.Pki.Tsp.TimeStampProtocol.CreateRequest(hash, hashOid, nonce)",
                ["input"] = new JsonObject { ["hash"] = Hex(imprint), ["hashOid"] = hashOid, ["nonce"] = requestNonce.ToString() },
                ["bouncyCastle"] = new JsonObject
                {
                    ["version"] = bc.Version,
                    ["messageImprintAlgOid"] = bc.MessageImprintAlgOid,
                    ["messageImprintDigest"] = Hex(bc.GetMessageImprintDigest()),
                    ["reqPolicy"] = bc.ReqPolicy,
                    ["nonce"] = bc.Nonce?.ToString(),
                    ["certReq"] = bc.CertReq,
                },
            });
        }

        o.WriteJson("tsp/tsp.json", new JsonObject
        {
            ["tokens"] = tokens,
            ["responses"] = new JsonArray(
                new JsonObject
                {
                    ["file"] = granted,
                    ["status"] = 0,
                    ["imprintAlgorithm"] = Oids.Dstu7564_256,
                    ["imprint"] = Hex(hash),
                    ["nonce"] = nonce.ToString(),
                    ["about"] = "TimeStampResp { granted, token over 32 zero bytes with the nonce }: ParseResponse accepts it for this imprint and nonce only",
                },
                new JsonObject
                {
                    ["file"] = rejection,
                    ["status"] = 2,
                    ["about"] = "TimeStampResp { rejection }, no token: ParseResponse throws",
                }),
            ["requests"] = requests,
        });
        o.WriteText("tsp/README.md", TspReadme);
    }

    private static JsonObject DescribeToken(PkiOutput o, string file, string coveredFile, bool embedded)
    {
        var cms = new CmsSignedData(o.Read(file));
        TstInfo info = UaPki.ReadTimeStamp(cms);
        var bc = new BcTimeStampToken(cms);
        return new JsonObject
        {
            ["file"] = file,
            ["covered"] = coveredFile,
            ["hashOid"] = info.MessageImprint.HashAlgorithm.Algorithm.Id,
            ["imprint"] = Hex(info.MessageImprint.GetHashedMessage()),
            ["policy"] = info.Policy.Id,
            ["serialNumber"] = bc.TimeStampInfo.SerialNumber.ToString(),
            ["genTime"] = Time(bc.TimeStampInfo.GenTime),
            ["nonce"] = info.Nonce?.Value.ToString(),
            ["tsaCertificateEmbedded"] = embedded,
            ["tsaCertificate"] = "hierarchy/tsa.cer",
            ["signerSerialNumber"] = bc.SignerID.SerialNumber.ToString(),
            ["signerDigestAlgorithm"] = cms.GetSignerInfos().GetSigners().Single().DigestAlgorithmID.Algorithm.Id,
            ["signerSignatureAlgorithm"] = cms.GetSignerInfos().GetSigners().Single().SignatureAlgorithm.Algorithm.Id,
        };
    }

    private static void CheckToken(PkiOutput o, string file, bool embedded, byte[]? covered = null)
    {
        covered ??= Covered;
        TimeStampToken token = TimeStampToken.Load(o.Read(file));
        Expect(token.Covers(covered) && !token.Covers([.. covered, 0]), $"{file} covers its data only");
        Certificate tsa = o.LoadCertificate("hierarchy/tsa.cer");
        var report = new VerificationReport("token");
        Certificate? found = token.Verify(covered, [], report, "ts");
        if (embedded)
        {
            Expect(found is not null && found.Equals(tsa) && report.IsValid, $"{file} verifies with the embedded TSA certificate");
        }
        else
        {
            Expect(found is null && token.FindSignerCertificate() is null, $"{file} has no TSA certificate");
            Expect(report.Checks.Any(c => c.Name == "ts: service certificate" && c.Status == CheckStatus.Warning), $"{file} warns");
            Expect(token.FindSignerCertificate(o.AllCertificates.Select(o.LoadCertificate))!.Equals(tsa), $"{file}: TSA found among known");
        }
    }

    // ---- ocsp/ ---------------------------------------------------------------------------------------------------

    private static void WriteOcsp(PkiOutput o)
    {
        Hierarchy pki = o.Pki;
        string zero = o.Write("ocsp/signer-zero-key-hash.der",
            OcspResponder.Encode(pki.IssuingCaOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate, zeroKeyHash: true)));
        string foreign = o.Write("ocsp/signer-by-root-responder.der",
            OcspResponder.Encode(pki.RootOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate)));
        string foreignZero = o.Write("ocsp/signer-by-root-responder-zero-key-hash.der",
            OcspResponder.Encode(pki.RootOcsp.Respond(pki.Signer.Certificate, pki.IssuingCa.Certificate, zeroKeyHash: true)));

        (string File, string About, string Responder, CheckStatus Status)[] responses =
        [
            (HierarchyFixtures.SignerOcsp, "good about the signer from the issuing CA's responder", "hierarchy/ocsp.cer", CheckStatus.Passed),
            (HierarchyFixtures.IssuingCaOcsp, "good about the issuing CA from the root's responder", "hierarchy/root-ocsp.cer", CheckStatus.Passed),
            (zero, "as \"Дія\" answers: CertID issuerKeyHash all zeros; matched by name hash and serial number", "hierarchy/ocsp.cer", CheckStatus.Passed),
            (foreign, "the root's responder answers about the signer: not authorized by the signer's issuer", "hierarchy/root-ocsp.cer", CheckStatus.Failed),
            (foreignZero, "unauthorized responder and zero issuerKeyHash", "hierarchy/root-ocsp.cer", CheckStatus.Failed),
        ];

        Certificate signer = o.LoadCertificate("hierarchy/signer.cer");
        Certificate ca = o.LoadCertificate("hierarchy/issuing-ca.cer");
        Certificate root = o.LoadCertificate(o.RootFile);
        var json = new JsonArray();
        foreach (var (file, about, responder, status) in responses)
        {
            bool aboutSigner = file != HierarchyFixtures.IssuingCaOcsp;
            JsonObject entry = DescribeResponse(o.Read(file));
            entry["file"] = file;
            entry["about"] = about;
            entry["subject"] = aboutSigner ? "hierarchy/signer.cer" : "hierarchy/issuing-ca.cer";
            entry["issuer"] = aboutSigner ? "hierarchy/issuing-ca.cer" : o.RootFile;
            entry["responderCertificate"] = responder;

            // PathValidationTests: the revocation check of the subject's path with only this response.
            if (aboutSigner)
            {
                var report = new VerificationReport("test");
                CertificatePathValidator.Validate(signer, [ca], [OcspResponse.Load(o.Read(file))],
                    new ValidationOptions { TrustAnchors = [root] }, DateTimeOffset.UtcNow, report, "path");
                Expect(report.Checks.Any(c => c.Name == "path: revocation of 'Test Signer'" && c.Status == status), $"{file}: revocation {status}");
                entry["pathRevocationCheck"] = new JsonObject { ["name"] = "path: revocation of 'Test Signer'", ["status"] = status.ToString() };
            }
            json.Add(entry);
        }

        OcspResponse zeroResponse = OcspResponse.Load(o.Read(zero));
        Expect(zeroResponse.Responses.Single().IssuerKeyHash.All(b => b == 0), "zero issuerKeyHash");
        Expect(zeroResponse.Find(signer, ca) is not null && zeroResponse.Find(signer, root) is null && zeroResponse.Find(ca, ca) is null,
            "zero-hash response is matched by name hash and serial number");

        // Requests made by the package, as BouncyCastle (LocalPkiServer) reads them.
        var requests = new JsonArray();
        foreach (string hashOid in new[] { Oids.Dstu7564_256, Oids.Gost34311 })
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(16);
            string file = o.Write($"ocsp/request-{Short(hashOid)}.der", OcspResponse.CreateRequest(signer, ca, hashOid, nonce));
            var bc = new BcOcspReq(o.Read(file));
            var id = bc.GetRequestList().Single().GetCertID();
            Asn1OctetString? nonceExtension = bc.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce);
            Expect(id.SerialNumber.Equals(pki.Signer.Certificate.SerialNumber) && id.HashAlgOid == hashOid, "BouncyCastle reads the package's OCSPRequest");
            requests.Add(new JsonObject
            {
                ["file"] = file,
                ["madeBy"] = "UA.Cryptography.Pki.Ocsp.OcspResponse.CreateRequest(signer, issuingCa, hashOid, nonce)",
                ["input"] = new JsonObject
                {
                    ["certificate"] = "hierarchy/signer.cer",
                    ["issuer"] = "hierarchy/issuing-ca.cer",
                    ["hashOid"] = hashOid,
                    ["nonce"] = Hex(nonce),
                },
                ["bouncyCastle"] = new JsonObject
                {
                    ["version"] = bc.Version,
                    ["requests"] = bc.GetRequestList().Length,
                    ["hashAlgOid"] = id.HashAlgOid,
                    ["issuerNameHash"] = Hex(id.GetIssuerNameHash()),
                    ["issuerKeyHash"] = Hex(id.GetIssuerKeyHash()),
                    ["serialNumber"] = id.SerialNumber.ToString(),
                    ["nonceExtensionValue"] = nonceExtension is null ? null : Hex(nonceExtension.GetOctets()),
                },
            });
        }

        o.WriteJson("ocsp/ocsp.json", new JsonObject { ["responses"] = json, ["requests"] = requests });
        o.WriteText("ocsp/README.md", OcspReadme);
    }

    /// <summary>What BouncyCastle reads from a full OCSPResponse.</summary>
    private static JsonObject DescribeResponse(byte[] der)
    {
        BasicOcspResponse basic = UaPki.ReadOcspResponse(der);
        ResponseData data = basic.TbsResponseData;
        return new JsonObject
        {
            ["responseStatus"] = 0,
            ["responseType"] = OcspObjectIdentifiers.PkixOcspBasic.Id,
            ["responderName"] = data.ResponderID.Name is { } name ? Hex(name.GetDerEncoded()) : null,
            ["producedAt"] = Time(data.ProducedAt.ToDateTime()),
            ["signatureAlgorithm"] = basic.SignatureAlgorithm.Algorithm.Id,
            ["signatureBitString"] = Hex(basic.GetSignatureOctets()),
            ["tbsResponseData"] = Hex(data.GetDerEncoded()),
            ["certificates"] = basic.Certs?.Count ?? 0,
            ["responses"] = new JsonArray(data.Responses.Cast<Asn1Encodable>().Select(SingleResponse.GetInstance).Select(s => (JsonNode)new JsonObject
            {
                ["hashAlgorithm"] = s.CertId.HashAlgorithm.Algorithm.Id,
                ["issuerNameHash"] = Hex(s.CertId.IssuerNameHash.GetOctets()),
                ["issuerKeyHash"] = Hex(s.CertId.IssuerKeyHash.GetOctets()),
                ["serialNumber"] = s.CertId.SerialNumber.Value.ToString(),
                ["certStatusTag"] = s.CertStatus.TagNo,
                ["thisUpdate"] = Time(s.ThisUpdate.ToDateTime()),
            }).ToArray()),
        };
    }

    public static string Short(string hashOid) => hashOid == Oids.Gost34311 ? "gost34311" : "dstu7564";

    private static void Throws(Action action, string what)
    {
        try
        {
            action();
        }
        catch (InvalidDataException)
        {
            return;
        }
        throw new InvalidOperationException($"pki oracle self-check failed: expected InvalidDataException ({what})");
    }

    private const string TspReadme = """
        # tsp/

        RFC 3161 time-stamp tokens of the hierarchy's TSA (`Support/TimeStampAuthority.cs`, BouncyCastle ASN.1, signed by
        the library: DSTU 4145 with the requested hash, signingCertificateV2), recorded by `tools/csharp-oracle -- pki`.
        `tsp.json` lists each file with what BouncyCastle reads from it.

        | File | What | C# test |
        |------|------|---------|
        | `covered.bin` | `"covered bytes"`, the data the tokens cover | |
        | `token-dstu7564.der`, `token-gost34311.der` | `Tsa.Stamp(covered, hash)`, TSA certificate inside; policies …2.3.4.1.1 / …2.3.1 | `TimeStampTokenTests.TokenCoversItsDataOnly` (both rows), `TestPkiTests.TimeStampTokenCoversDataAndIsSignedByTheTsa` (both rows; C# stamps 100 random bytes) |
        | `token-*-no-certificate.der` | the same without the TSA certificate: found among known certificates by issuer and serial only | `TimeStampTokenTests.ServiceCertificateIsFoundAmongKnownOnesWhenNotEmbedded`, `TestPkiTests.TimeStampSignerIsFoundByIssuerAndSerialWhenNotEmbedded` (C# stamps `[1, 2, 3]`) |
        | `data.bin`, `token-dstu7564-over-data.der` | a genuine token over `"data"`, to put into a CAdES signature over `"data"` as its signature time-stamp (imprint fails) | `TimeStampTokenTests.SignatureTimeStampOverOtherBytesFailsTheSignature` |
        | `response-granted.der` | `TimeStampResp { granted, token }` as `LocalPkiServer` answers: token over 32 zero bytes (DSTU 7564) with the nonce in `tsp.json` | `HttpServicesTests.ForgedTimeStampResponsesAreRejected` |
        | `response-rejection.der` | `TimeStampResp { rejection }` without a token | `HttpServicesTests.ForgedTimeStampResponsesAreRejected` |
        | `request-*.der` | `TimeStampReq` made by the C# package (`TimeStampProtocol.CreateRequest`) and BouncyCastle's reading of it (`TimeStampRequest`) in `tsp.json` | `HttpServicesTests.TimeStampServiceAnswersTheRequest` (LocalPkiServer parses the request with BouncyCastle) |

        A Rust test that needs a token over bytes it makes at run time (a signature value) signs one itself with the TSA key
        in `hierarchy/keys.json`; the CAdES/XAdES fixtures carry tokens over their own signature values.
        """;

    private const string OcspReadme = """
        # ocsp/

        OCSP responses of the hierarchy's responders (`Support/OcspResponder.cs`: BouncyCastle ASN.1, DSTU 4145 +
        DSTU 7564 over the DER tbsResponseData, signature BIT STRING wrapping an OCTET STRING with D, DSTU 7564 CertID, the
        responder's certificate inside), recorded by `tools/csharp-oracle -- pki`. All files are full `OCSPResponse`s.
        The two plain "good" responses live in `hierarchy/` (`ocsp-signer.der`, `ocsp-issuing-ca.der`).

        `ocsp.json` lists every response (including the two in `hierarchy/`) with what BouncyCastle reads from it (responder
        name DER, producedAt, the DER tbsResponseData, CertID fields, status tag, thisUpdate) and, for responses about the
        signer, the status of the check `path: revocation of 'Test Signer'` when the signer's path (`[issuing-ca]`, anchor
        `root`) is validated with only that response.

        | File | What | C# test |
        |------|------|---------|
        | `signer-zero-key-hash.der` | about the signer from its issuer's responder, CertID issuerKeyHash all zeros ("Дія") → Passed | `PathValidationTests.OcspWithAZeroIssuerKeyHashIsMatchedByNameAndSerial` |
        | `signer-by-root-responder.der` | about the signer from the root's responder (not authorized by the issuing CA) → Failed | `PathValidationTests.OcspFromAnUnauthorizedResponderIsRejected` |
        | `signer-by-root-responder-zero-key-hash.der` | the same with a zero issuerKeyHash → Failed | `PathValidationTests.OcspWithAZeroIssuerKeyHashIsMatchedByNameAndSerial` |
        | `request-*.der` | `OCSPRequest` made by the C# package (`OcspResponse.CreateRequest(signer, issuing CA, hash, nonce)`) and BouncyCastle's reading of it (`OcspReq`: CertID, nonce extension) in `ocsp.json` | `HttpServicesTests.OcspServiceAnswersAboutTheCertificate` |

        Also read by the Rust ports of `TestPkiTests.OcspResponseIsSignedByTheResponderAndGood` and
        `PathValidationTests.SyntheticSignerWithOcspIsFullyValidated` (with the `hierarchy/` responses).
        """;
}
