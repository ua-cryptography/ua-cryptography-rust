using System.Text.Json;
using Org.BouncyCastle.Crypto.Digests;

namespace CSharpOracle.Generators;

/// <summary>
/// DSTU 7564 (Kupyna) hashes computed by BouncyCastle for random messages around both block sizes and the 12-byte
/// length field, at 256, 384 and 512 bits (the inputs as Dstu7564Tests.MatchesBouncyCastle draws them).
/// </summary>
internal sealed class Dstu7564Bc : IFixtureGenerator
{
    private static readonly int[] HashSizes = [256, 384, 512];
    private static readonly int[] Lengths = [0, 1, 51, 52, 53, 63, 64, 65, 115, 116, 117, 127, 128, 129, 1000, 4097];

    public string Name => "dstu7564-bc";

    public void Generate(string directory)
    {
        var cases = new List<object>();
        foreach (int bits in HashSizes)
        {
            var random = new Random(bits);
            foreach (int length in Lengths)
            {
                var data = new byte[length];
                random.NextBytes(data);
                var digest = new Dstu7564Digest(bits);
                digest.BlockUpdate(data, 0, data.Length);
                var hash = new byte[bits / 8];
                digest.DoFinal(hash, 0);
                cases.Add(new { bits, message = Convert.ToHexString(data), hash = Convert.ToHexString(hash) });
            }
        }
        File.WriteAllText(Path.Combine(directory, "dstu7564-bc.json"),
            JsonSerializer.Serialize(cases, new JsonSerializerOptions { WriteIndented = true }));
    }
}
