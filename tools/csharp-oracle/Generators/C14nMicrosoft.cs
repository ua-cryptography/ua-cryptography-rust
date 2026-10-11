using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml;
using UA.Cryptography.Pki.Xml;

namespace CSharpOracle.Generators;

/// <summary>
/// Microsoft's canonicalization (System.Security.Cryptography.Xml) for every case XmlCanonicalizerTests checks: whole
/// documents with the four methods, exclusive subtrees, the "#target" reference digest, InclusiveNamespaces prefix
/// lists, the enveloped-signature transform and a XAdES document; plus the C# canonicalizer's own output for every
/// element subtree of those documents and of a few documents that probe the parser (line ends, PIs, ordering).
/// </summary>
internal sealed class C14nMicrosoft : IFixtureGenerator
{
    private const string InclusiveC14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    private const string InclusiveC14NWithComments = InclusiveC14N + "#WithComments";
    private const string ExclusiveC14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string ExclusiveC14NWithComments = ExclusiveC14N + "WithComments";
    private static readonly string[] Algorithms = [InclusiveC14N, InclusiveC14NWithComments, ExclusiveC14N, ExclusiveC14NWithComments];

    // XmlCanonicalizerTests.Documents, verbatim.
    private static readonly string[] Documents =
    [
        """<a xmlns="urn:a" xmlns:b="urn:b" z="1" b:y="2" a="3"><b:c/><d xmlns=""/><e xmlns:b="urn:b">text &amp; &lt; &gt; "q" 'a'</e></a>""",
        "<?pi data?>\n<!-- before -->\n<root><!-- inner --><?p?><x>1</x></root>\n<!-- after -->\n<?last?>",
        """<r a="x&#9;y&#10;z&#13;w" b='"quoted"' c="&lt;&amp;&gt;"/>""",
        "<r>  <![CDATA[ <x> & ]]>  \n\t<s>\r\n</s> </r>",
        """<r xml:lang="uk" xmlns:p="urn:p"><s xml:space="preserve" p:a="1"><t Id="target"><u/></t></s></r>""",
        """<r xmlns:unused="urn:u" xmlns:p="urn:p"><p:x p:attr="1" Id="target"><y/></p:x></r>""",
        """<r xmlns="urn:r"><s xmlns="" Id="target"><t xmlns="urn:r"/><v/></s></r>""",
        """<p:r xmlns:p="urn:1"><p:s xmlns:p="urn:2" Id="target"><p:t xmlns:p="urn:2"/></p:s></p:r>""",
        """<doc xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:x="urn:x"><ds:Signature Id="target"><ds:SignedInfo x:a="b">Ж ї є ґ</ds:SignedInfo></ds:Signature></doc>""",
    ];

    // Documents beyond the C# tests that probe what the parser hands the canonicalizer.
    private static readonly string[] ProbeDocuments =
    [
        "<r><!-- a\r\nb\rc --><?p x\r\ny?><s>a\r&amp;b\r\nc&#13;d\r</s></r>",
        "<r><?p   data  ?><?q?><?t \t x?></r>",
        "<r a=\"x\ty\nz\r\nw\" b=\"&#9;&#10;&#13;\"/>",
        "<r xmlns:a=\"urn:\" xmlns:b=\"urn:\U0001F600\" xmlns:c=\"urn:z\" c:x=\"3\" b:x=\"2\" a:x=\"1\" x=\"0\"/>",
        "<r  a = \"1\"  ><s\n/><t\tb='2'></t ></r >",
        "<ж:е xmlns:ж=\"urn:ж\" xmlns:я=\"urn:я\" я:б=\"2\" ж:а=\"1\"><я:в/></ж:е>",
        "﻿<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<!--c-->\r\n<r xml:base=\"http://e/\" xml:lang=\"en\"><s xml:lang=\"uk\"><t/></s></r>\r\n",
        "<r xmlns=\"urn:d\" xmlns:p=\"urn:p\" xmlns:q=\"urn:q\"><p:s xmlns=\"\"><t xmlns:p=\"urn:p2\" p:a=\"1\" q:b=\"2\"/></p:s></r>",
    ];

    public string Name => "c14n-microsoft";

    public void Generate(string directory)
    {
        var fixture = new
        {
            documents = Documents.Select(TestDocument).ToArray(),
            prefixLists = PrefixLists(),
            enveloped = Enveloped(),
            xades = Xades(),
            reference = Documents.Concat(ProbeDocuments).Select(ReferenceDocument).ToArray(),
        };
        var options = new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        File.WriteAllText(Path.Combine(directory, "c14n-microsoft.json"), JsonSerializer.Serialize(fixture, options));
    }

    private static XmlDocument Load(string xml) => XmlSafe.Load(Encoding.UTF8.GetBytes(xml));

    private static string Text(byte[] canonical) => Encoding.UTF8.GetString(canonical);

    private static byte[] Microsoft(Transform transform, XmlDocument document)
    {
        transform.LoadInput(document);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static Transform MicrosoftTransform(string algorithm) => algorithm switch
    {
        InclusiveC14N => new XmlDsigC14NTransform(false),
        InclusiveC14NWithComments => new XmlDsigC14NTransform(true),
        ExclusiveC14N => new XmlDsigExcC14NTransform(false),
        _ => new XmlDsigExcC14NTransform(true),
    };

    private static List<XmlElement> Elements(XmlDocument document) => document.GetElementsByTagName("*").Cast<XmlElement>().ToList();

    // The test's expectation must agree with the C# canonicalizer, or the fixture would pin a disagreement.
    private static string Checked(byte[] microsoft, byte[] ours, string what)
    {
        if (!microsoft.AsSpan().SequenceEqual(ours))
            throw new InvalidOperationException($"Microsoft and XmlCanonicalizer disagree: {what}");
        return Text(microsoft);
    }

    private static object TestDocument(string xml)
    {
        var whole = Algorithms.ToDictionary(a => a, a => Checked(
            Microsoft(MicrosoftTransform(a), Load(xml)), XmlCanonicalizer.Canonicalize(Load(xml), a), $"{a} of {xml}"));

        XmlDocument document = Load(xml);
        var subtrees = new List<object>();
        List<XmlElement> elements = Elements(document);
        for (int i = 0; i < elements.Count; i++)
        {
            XmlElement element = elements[i];
            if (element.SelectNodes("descendant-or-self::*/@*")!.Cast<XmlAttribute>().Any(a => a.Value.IndexOfAny(['\t', '\n', '\r']) >= 0))
                continue;
            string canonical = Checked(Microsoft(new XmlDsigExcC14NTransform(false), Load(element.OuterXml)),
                XmlCanonicalizer.Canonicalize(element, ExclusiveC14N), $"subtree {i} of {xml}");
            subtrees.Add(new { element = i, canonical });
        }
        return new { xml, whole, exclusiveSubtrees = subtrees, target = Target(xml) };
    }

    // SignedXml's digest of the reference "#target" (inclusive C14N) and the C# canonical bytes that hash to it.
    private static object? Target(string xml)
    {
        XmlDocument document = Load(xml);
        if (document.SelectSingleNode("//*[@Id='target']") is not XmlElement target)
            return null;
        var signed = new SignedXml(document) { SigningKey = RSA.Create(2048) };
        var reference = new Reference("#target") { DigestMethod = SignedXml.XmlDsigSHA256Url };
        signed.AddReference(reference);
        signed.ComputeSignature();
        byte[] ours = XmlCanonicalizer.Canonicalize(target, InclusiveC14N);
        if (!SHA256.HashData(ours).AsSpan().SequenceEqual(reference.DigestValue!))
            throw new InvalidOperationException($"SignedXml digest disagrees: {xml}");
        int index = Elements(document).IndexOf(target);
        return new { element = index, sha256 = Convert.ToHexString(reference.DigestValue!), canonical = Text(ours) };
    }

    private static object PrefixLists()
    {
        const string xml = """<r xmlns:a="urn:a" xmlns:b="urn:b" xmlns="urn:d"><x><y a:z="1"/></x></r>""";
        var cases = new List<object>();
        foreach (string list in new[] { "b", "#default", "b #default", "a b" })
        {
            string canonical = Checked(Microsoft(new XmlDsigExcC14NTransform(false, list), Load(xml)),
                XmlCanonicalizer.Canonicalize(Load(xml), ExclusiveC14N, list.Split(' ')), $"prefix list {list}");
            cases.Add(new { prefixList = list, canonical });
        }
        return new { xml, cases };
    }

    private static object Enveloped()
    {
        const string xml = """<doc a="1"><data>value</data><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature><tail/></doc>""";
        XmlDocument document = Load(xml);
        XmlNode signature = document.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;
        XmlDocument without = Load(xml);
        XmlNode removed = without.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#")[0]!;
        removed.ParentNode!.RemoveChild(removed);
        string canonical = Checked(Microsoft(new XmlDsigC14NTransform(false), without),
            XmlCanonicalizer.Canonicalize(document, InclusiveC14N, excluded: signature), "enveloped");
        return new { xml, canonical };
    }

    private static object Xades()
    {
        string xml = XadesBuilder.Build("test"u8.ToArray(), "data.txt", Hierarchy.Shared, UA.Cryptography.Tests.Support.Oids.Dstu7564_256).OuterXml;
        XmlDocument document = Load(xml);
        List<XmlElement> elements = Elements(document);
        var subtrees = elements.Select((e, i) => new
        {
            element = i,
            canonical = Checked(XadesBuilder.Canonicalize(e), XmlCanonicalizer.Canonicalize(e, ExclusiveC14N), $"XAdES subtree {i}"),
        }).ToArray();
        string inclusive = Checked(Microsoft(new XmlDsigC14NTransform(false), Load(xml)),
            XmlCanonicalizer.Canonicalize(Load(xml), InclusiveC14N), "XAdES document");
        return new { xml, exclusiveSubtrees = subtrees, inclusiveDocument = inclusive };
    }

    // The C# canonicalizer (the reference of the port) over the document and every element, with every method.
    private static object ReferenceDocument(string xml)
    {
        XmlDocument document = Load(xml);
        List<XmlElement> elements = Elements(document);
        var cases = new List<object>();
        foreach (string algorithm in Algorithms)
        {
            cases.Add(new { element = (int?)null, algorithm, canonical = Text(XmlCanonicalizer.Canonicalize(document, algorithm)) });
            for (int i = 0; i < elements.Count; i++)
                cases.Add(new { element = (int?)i, algorithm, canonical = Text(XmlCanonicalizer.Canonicalize(elements[i], algorithm)) });
        }
        string? microsoft = Text(Microsoft(new XmlDsigC14NTransform(true), Load(xml)));
        return new { xml, cases, microsoftInclusiveWithComments = microsoft };
    }
}
