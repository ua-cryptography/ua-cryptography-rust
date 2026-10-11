using System.Text.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using UA.Cryptography.Dstu4145;
using UA.Cryptography.Math;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcDstu4145NamedCurves = Org.BouncyCastle.Asn1.UA.Dstu4145NamedCurves;
using BcDstu4145Signer = Org.BouncyCastle.Crypto.Signers.Dstu4145Signer;
using BigInteger = System.Numerics.BigInteger;

namespace CSharpOracle.Generators;

/// <summary>
/// DSTU 4145 in the polynomial basis as BouncyCastle sees it, for the ports of BouncyCastleCrossCheckTests: the named
/// curves of BouncyCastle, kP of BouncyCastle, BouncyCastle signatures under synthetic keys, and signatures of the
/// C# library with a fixed presignature that BouncyCastle verified while recording (the Rust port must reproduce them
/// bit for bit, which makes its own signatures checkable against BouncyCastle). Also the output of the Appendix А
/// generator of the C# library for a fixed state.
/// </summary>
internal sealed class Dstu4145Bc : IFixtureGenerator
{
    private const int MultiplesPerCurve = 3;
    private const int SignaturesPerCurve = 2;

    public string Name => "dstu4145-bc";

    public void Generate(string directory)
    {
        DerObjectIdentifier[] oids = BcDstu4145NamedCurves.GetOids();
        var fixture = new
        {
            curves = Enumerable.Range(0, oids.Length).Select(i => Curve(i, oids[i])).ToArray(),
            randomGenerator = RandomGeneratorOutput(),
        };
        File.WriteAllText(Path.Combine(directory, "dstu4145-bc.json"),
            JsonSerializer.Serialize(fixture, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static object Curve(int index, DerObjectIdentifier oid)
    {
        ECDomainParameters bc = BcDstu4145NamedCurves.GetByOid(oid);
        var f2m = (F2mCurve)bc.Curve;
        Dstu4145DomainParameters ours = Dstu4145NamedCurves.Polynomial(f2m.M);
        ECPoint g = bc.G.Normalize();
        var random = new Random(index);
        return new
        {
            index,
            oid = oid.Id,
            m = f2m.M,
            k1 = f2m.K1,
            k2 = f2m.K2,
            k3 = f2m.K3,
            a = Hex(f2m.A.ToBigInteger()),
            b = Hex(f2m.B.ToBigInteger()),
            n = Hex(bc.N),
            gx = Hex(g.AffineXCoord.ToBigInteger()),
            gy = Hex(g.AffineYCoord.ToBigInteger()),
            multiples = Enumerable.Range(0, MultiplesPerCurve).Select(_ => Multiple(bc, ours, random)).ToArray(),
            bouncyCastleSignatures = Enumerable.Range(0, SignaturesPerCurve).Select(_ => BcSignature(bc, ours)).ToArray(),
            csharpSignatures = Enumerable.Range(0, SignaturesPerCurve).Select(_ => CSharpSignature(bc, ours)).ToArray(),
        };
    }

    /// <summary>kG computed by BouncyCastle; k as ScalarMultiplicationMatchesBouncyCastle draws it.</summary>
    private static object Multiple(ECDomainParameters bc, Dstu4145DomainParameters ours, Random random)
    {
        BigInteger k = TestUtil.RandomInteger(random, ours.Field.M) % ours.N;
        ECPoint kg = bc.G.Multiply(ToBc(k)).Normalize();
        return new { k = Hex(k), x = Hex(kg.AffineXCoord.ToBigInteger()), y = Hex(kg.AffineYCoord.ToBigInteger()) };
    }

    /// <summary>A BouncyCastle signature of a random hash under a synthetic key (BouncyCastle → ours).</summary>
    private static object BcSignature(ECDomainParameters bc, Dstu4145DomainParameters ours)
    {
        Dstu4145KeyPair key = new Dstu4145Signer(ours).GenerateKeyPair();
        byte[] hash = new SecureRandom().GenerateSeed(32);
        var bcSigner = new BcDstu4145Signer();
        bcSigner.Init(true, new ParametersWithRandom(new ECPrivateKeyParameters(ToBc(key.PrivateKey), bc), new SecureRandom()));
        BcBigInteger[] rs = bcSigner.GenerateSignature(hash.Reverse().ToArray());
        return new
        {
            qx = Hex(key.PublicKey.AffineX.ToBigInteger()),
            qy = Hex(key.PublicKey.AffineY.ToBigInteger()),
            hash = Convert.ToHexString(hash),
            r = Hex(rs[0]),
            s = Hex(rs[1]),
        };
    }

    /// <summary>
    /// A signature of the C# library with a fixed presignature e, verified by BouncyCastle here (ours → BouncyCastle).
    /// </summary>
    private static object CSharpSignature(ECDomainParameters bc, Dstu4145DomainParameters ours)
    {
        var signer = new Dstu4145Signer(ours);
        Dstu4145KeyPair key = signer.GenerateKeyPair();
        byte[] hash = new SecureRandom().GenerateSeed(32);
        FieldElement h = Dstu4145Encoding.HashToFieldElement(hash, ours.Field);
        while (true)
        {
            Dstu4145Presignature presignature = signer.ComputePresignature();
            (BigInteger R, BigInteger S)? rs = signer.Sign(key.PrivateKey, h, presignature);
            if (rs is null)
                continue;
            byte[] signature = Dstu4145Encoding.EncodeSignature(rs.Value.R, rs.Value.S, ours.MinimumSignatureBits);

            var verifier = new BcDstu4145Signer();
            var bcPublic = new ECPublicKeyParameters(bc.Curve.CreatePoint(
                ToBc(key.PublicKey.AffineX.ToBigInteger()), ToBc(key.PublicKey.AffineY.ToBigInteger())), bc);
            verifier.Init(false, bcPublic);
            if (!verifier.VerifySignature(hash.Reverse().ToArray(), ToBc(rs.Value.R), ToBc(rs.Value.S)))
                throw new InvalidOperationException("BouncyCastle rejected a signature of the C# library.");

            return new
            {
                d = Hex(key.PrivateKey),
                qx = Hex(key.PublicKey.AffineX.ToBigInteger()),
                qy = Hex(key.PublicKey.AffineY.ToBigInteger()),
                hash = Convert.ToHexString(hash),
                e = Hex(presignature.E),
                r = Hex(rs.Value.R),
                s = Hex(rs.Value.S),
                signature = Convert.ToHexString(signature),
                bouncyCastleVerified = true,
            };
        }
    }

    /// <summary>64 bytes of the Appendix А generator for the state of RandomGeneratorTests.</summary>
    private static object RandomGeneratorOutput()
    {
        byte[] key = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        byte[] seed = [1, 2, 3, 4, 5, 6, 7, 8];
        const ulong dateTime = 0x0123456789ABCDEF;
        var generator = new Dstu4145RandomGenerator(key, seed, dateTime);
        var output = new byte[64];
        generator.GetBytes(output);
        return new
        {
            key = Convert.ToHexString(key),
            seed = Convert.ToHexString(seed),
            dateTime = dateTime.ToString("X16"),
            output = Convert.ToHexString(output),
        };
    }

    private static BcBigInteger ToBc(BigInteger v) => new(1, v.ToByteArray(isUnsigned: true, isBigEndian: true));

    private static string Hex(BigInteger v) => UA.Cryptography.Math.Hex.FromBigInteger(v);

    private static string Hex(BcBigInteger v) => v.ToString(16).ToUpperInvariant();
}
