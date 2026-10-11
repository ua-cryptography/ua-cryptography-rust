namespace CSharpOracle;

/// <summary>One set of fixtures: a folder testdata/oracle/&lt;Name&gt;/ that one group of Rust tests reads.</summary>
public interface IFixtureGenerator
{
    /// <summary>The folder name under testdata/oracle, in kebab-case.</summary>
    string Name { get; }

    /// <summary>Writes the fixtures into <paramref name="directory"/>, which exists and may hold older files.</summary>
    void Generate(string directory);
}
