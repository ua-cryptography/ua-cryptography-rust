using System.Reflection;
using CSharpOracle;

// Runs every fixture generator, or the ones named on the command line, writing under testdata/oracle/<name>/.
string repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../.."));
string outputRoot = Path.Combine(repoRoot, "testdata", "oracle");

var generators = Assembly.GetExecutingAssembly().GetTypes()
    .Where(t => typeof(IFixtureGenerator).IsAssignableFrom(t) && t is { IsInterface: false, IsAbstract: false })
    .Select(t => (IFixtureGenerator)Activator.CreateInstance(t)!)
    .OrderBy(g => g.Name, StringComparer.Ordinal)
    .ToList();

var selected = args.Length == 0 ? generators : generators.Where(g => args.Contains(g.Name)).ToList();
if (selected.Count == 0)
{
    Console.Error.WriteLine($"No generator matches. Known: {string.Join(", ", generators.Select(g => g.Name))}");
    return 2;
}

foreach (IFixtureGenerator generator in selected)
{
    string directory = Path.Combine(outputRoot, generator.Name);
    Directory.CreateDirectory(directory);
    generator.Generate(directory);
    Console.WriteLine($"{generator.Name}: {directory}");
}
return 0;
