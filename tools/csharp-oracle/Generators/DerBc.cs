using System.Globalization;
using System.Text.Json;
using Org.BouncyCastle.Asn1;
using UA.Cryptography.Pki.Asn1;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using KeyUsage = Org.BouncyCastle.Asn1.X509.KeyUsage;

namespace CSharpOracle.Generators;

/// <summary>
/// BouncyCastle's DER encodings for the cases of DerTests (INTEGER, OBJECT IDENTIFIER, length forms, SET OF order, named
/// bits, times, a BER indefinite-length sequence), plus how the C# reader parses UTCTime / GeneralizedTime text forms.
/// </summary>
internal sealed class DerBc : IFixtureGenerator
{
    private static readonly string[] Integers =
    [
        "0", "1", "-1", "127", "128", "255", "256", "-128", "-129", "-32768",
        "123456789012345678901234567890123456789012345678901234567890",
        "-123456789012345678901234567890123456789012345678901234567890",
    ];

    private static readonly string[] ObjectIdentifiers =
    [
        "1.2.804.2.1.1.1.1.3.1.1", "1.2.804.2.1.1.1.1.3.6.1.1", "1.2.840.113549.1.9.16.2.47", "2.5.29.15",
        "0.9.2342.19200300.100.1.1", "2.999.1", "1.3.6.1.4.1.18446744073709551616.5",
    ];

    private static readonly int[] Lengths = [0, 1, 127, 128, 255, 256, 65535, 65536];

    private static readonly int[] KeyUsages =
    [
        KeyUsage.DigitalSignature,
        KeyUsage.DigitalSignature | KeyUsage.NonRepudiation,
        KeyUsage.KeyCertSign | KeyUsage.CrlSign,
        KeyUsage.KeyAgreement,
        KeyUsage.DecipherOnly,
    ];

    // Time contents the C# reader accepts or refuses: (tag, text).
    private static readonly (byte Tag, string Text)[] Times =
    [
        (Asn1Tag.UtcTime, "261010123456Z"), (Asn1Tag.UtcTime, "2610101234Z"), (Asn1Tag.UtcTime, "491231235959Z"),
        (Asn1Tag.UtcTime, "500101000000Z"), (Asn1Tag.UtcTime, "261010123456+0130"), (Asn1Tag.UtcTime, "261010123456-0200"),
        (Asn1Tag.UtcTime, "261010123456"), (Asn1Tag.UtcTime, "991231233000-0100"), (Asn1Tag.UtcTime, "261310123456Z"),
        (Asn1Tag.UtcTime, "261010123460Z"), (Asn1Tag.UtcTime, "26101012345Z"), (Asn1Tag.UtcTime, ""),
        (Asn1Tag.UtcTime, "260229000000Z"), (Asn1Tag.UtcTime, "240229000000Z"),
        (Asn1Tag.GeneralizedTime, "20261010123456Z"), (Asn1Tag.GeneralizedTime, "202610101234Z"),
        (Asn1Tag.GeneralizedTime, "20261010123456.5Z"), (Asn1Tag.GeneralizedTime, "20261010123456,25Z"),
        (Asn1Tag.GeneralizedTime, "20261010123456.1234567Z"), (Asn1Tag.GeneralizedTime, "20261010123456.12345678Z"),
        (Asn1Tag.GeneralizedTime, "20261010123456.Z"), (Asn1Tag.GeneralizedTime, "20261010123456+1400"),
        (Asn1Tag.GeneralizedTime, "20261010123456+1500"), (Asn1Tag.GeneralizedTime, "20261010123456-0000"),
        (Asn1Tag.GeneralizedTime, "20261010123456"), (Asn1Tag.GeneralizedTime, "2026101012Z"),
        (Asn1Tag.GeneralizedTime, "20261010123456+01"), (Asn1Tag.GeneralizedTime, "00010101000000Z"),
        (Asn1Tag.GeneralizedTime, "99991231235959Z"), (Asn1Tag.GeneralizedTime, " 20261010123456Z"),
        (Asn1Tag.GeneralizedTime, "20261010123456.5+0100"), (Asn1Tag.GeneralizedTime, "2026101012345Z"),
        (Asn1Tag.GeneralizedTime, "202610101234567Z"),
    ];

    public string Name => "der-bc";

    public void Generate(string directory)
    {
        var fixture = new
        {
            integers = Integers.Select(v => new { value = v, der = Hex(new DerInteger(new BcBigInteger(v)).GetDerEncoded()) }).ToArray(),
            objectIdentifiers = ObjectIdentifiers.Select(o => new { oid = o, der = Hex(new DerObjectIdentifier(o).GetDerEncoded()) }).ToArray(),
            octetStringHeaders = Lengths.Select(OctetStringHeader).ToArray(),
            setsOf = SetsOf(),
            keyUsages = KeyUsages.Select(u => new { bouncyCastleBits = u, der = Hex(new KeyUsage(u).GetDerEncoded()) }).ToArray(),
            times = TimesOf(new DateTimeOffset(2026, 10, 10, 12, 34, 56, TimeSpan.Zero)),
            berSequence = Hex(BerSequence()),
            readerTimes = Times.Select(t => new { tag = t.Tag, text = t.Text, utc = ReadTime(t.Tag, t.Text) }).ToArray(),
        };
        File.WriteAllText(Path.Combine(directory, "der-bc.json"),
            JsonSerializer.Serialize(fixture, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string Hex(byte[] data) => Convert.ToHexString(data);

    // The header BouncyCastle writes before the contents; the contents themselves are the input, written back verbatim.
    private static object OctetStringHeader(int length)
    {
        byte[] content = new byte[length];
        new Random(length).NextBytes(content);
        byte[] encoded = new DerOctetString(content).GetDerEncoded();
        if (!encoded.AsSpan(encoded.Length - length).SequenceEqual(content))
            throw new InvalidOperationException("BouncyCastle changed the contents.");
        return new { length, header = Hex(encoded[..^length]) };
    }

    private static object[] SetsOf()
    {
        var random = new Random(4145);
        var rounds = new List<object>();
        for (int round = 0; round < 50; round++)
        {
            byte[][] items = Enumerable.Range(0, random.Next(1, 8))
                .Select(_ => Der.OctetString(Enumerable.Range(0, random.Next(0, 5)).Select(_ => (byte)random.Next(3)).ToArray()))
                .ToArray();
            var bc = new DerSet(items.Select(i => (Asn1Encodable)Asn1Object.FromByteArray(i)).ToArray());
            rounds.Add(new { items = items.Select(Hex).ToArray(), der = Hex(bc.GetDerEncoded()) });
        }
        return rounds.ToArray();
    }

    private static object TimesOf(DateTimeOffset time) => new
    {
        utc = time.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
        utcTime = Hex(new DerUtcTime(time.UtcDateTime, 2049).GetDerEncoded()),
        generalizedTime = Hex(new DerGeneralizedTime(time.UtcDateTime).GetDerEncoded()),
    };

    private static byte[] BerSequence()
    {
        var stream = new MemoryStream();
        using (var generator = new BerSequenceGenerator(stream))
        {
            generator.AddObject(new BerOctetString([new DerOctetString("ab"u8.ToArray()), new DerOctetString("cd"u8.ToArray())]));
            generator.AddObject(DerInteger.ValueOf(5));
        }
        return stream.ToArray();
    }

    // The C# reader's answer: the UTC instant to the tick, or null when it refuses the text.
    private static string? ReadTime(byte tag, string text)
    {
        try
        {
            DateTimeOffset t = Asn1Node.Parse(Der.Encode(tag, System.Text.Encoding.ASCII.GetBytes(text))).GetTime();
            return t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture);
        }
        catch (Exception e) when (e is InvalidDataException or FormatException or ArgumentException)
        {
            return null;
        }
    }
}
