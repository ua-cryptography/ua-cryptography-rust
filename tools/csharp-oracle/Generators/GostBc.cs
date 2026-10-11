using System.Text.Json;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using UA.Cryptography.Gost;

namespace CSharpOracle.Generators;

/// <summary>
/// GOST 28147-89 blocks and GOST 34.311-95 hashes computed by BouncyCastle for the four substitution tables of
/// GostTests (the inputs as the C# tests draw them), and the BouncyCastle "D-Test" and "D-A" tables themselves.
/// </summary>
internal sealed class GostBc : IFixtureGenerator
{
    private static readonly int[] HashLengths = [0, 1, 31, 32, 33, 63, 64, 65, 100, 1000];
    private const int BlockCount = 50;

    public string Name => "gost-bc";

    public void Generate(string directory)
    {
        var sboxes = new (string Name, string Hex)[]
        {
            ("DKE No. 1 (default)", Expand(Convert.ToHexString(Gost34311.DefaultDke))),
            ("DKE of UCC = D-Test", Expand("4A92D80E6B1C7F53EB4C6DFA23810759581DA342EFC7609B7DA1089FE46CB2536C715FD84A9E03B24BA0721D36859CFEDB413F590AE7682C1FD057A4923E6B8C")),
            ("DKE of CZO 2005", Expand("8BC217ED36594AF01F74E23DCB9A6058FED7852014ABC3694B08A7359D621ECFE87FD35AB4192C607AEC14D283B0F569B09641AE8F5DC327C7129A6EF48D350B")),
            ("CryptoPro D-A", Convert.ToHexString(Gost28147Engine.GetSBox("D-A"))),
        };

        var fixture = new
        {
            bouncyCastleSboxes = new
            {
                dTest = Convert.ToHexString(Gost28147Engine.GetSBox("D-Test")),
                dA = Convert.ToHexString(Gost28147Engine.GetSBox("D-A")),
            },
            sboxes = sboxes.Select(s => new
            {
                name = s.Name,
                sbox = s.Hex,
                blocks = Blocks(s.Name, s.Hex),
                hashes = Hashes(s.Name, s.Hex),
            }).ToArray(),
        };
        File.WriteAllText(Path.Combine(directory, "gost-bc.json"),
            JsonSerializer.Serialize(fixture, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string Expand(string dke) => Convert.ToHexString(Gost28147.ExpandDke(Convert.FromHexString(dke)));

    private static object[] Blocks(string name, string sboxHex)
    {
        byte[] sbox = Convert.FromHexString(sboxHex);
        var random = new Random(name.Length * 31 + sboxHex[7]);
        var blocks = new List<object>();
        for (int i = 0; i < BlockCount; i++)
        {
            var key = new byte[32];
            var block = new byte[8];
            random.NextBytes(key);
            random.NextBytes(block);
            var engine = new Gost28147Engine();
            engine.Init(true, new ParametersWithSBox(new KeyParameter(key), sbox));
            var cipher = new byte[8];
            engine.ProcessBlock(block, 0, cipher, 0);
            blocks.Add(new
            {
                key = Convert.ToHexString(key),
                plaintext = Convert.ToHexString(block),
                ciphertext = Convert.ToHexString(cipher),
            });
        }
        return blocks.ToArray();
    }

    private static object[] Hashes(string name, string sboxHex)
    {
        byte[] sbox = Convert.FromHexString(sboxHex);
        var random = new Random(name.Length * 17 + sboxHex[5]);
        var hashes = new List<object>();
        foreach (int length in HashLengths)
        {
            var data = new byte[length];
            random.NextBytes(data);
            var digest = new Gost3411Digest(sbox);
            digest.BlockUpdate(data, 0, data.Length);
            var hash = new byte[32];
            digest.DoFinal(hash, 0);
            hashes.Add(new { message = Convert.ToHexString(data), hash = Convert.ToHexString(hash) });
        }
        return hashes.ToArray();
    }
}
